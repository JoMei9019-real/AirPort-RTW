/* Modified by X1REN41L on 2026-10-02 for AirPortRTW 1.0.0; see the repository NOTICE.md. */
/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * AirPortRTW 2.0.0-beta.17 — Ventura IO80211 AWDL/P2P TX-handoff diagnostics.
 *
 * This file deliberately implements only payload ABIs present in the pinned
 * the kernel SDK. Verified Ventura payload ABIs are handled explicitly. Unknown AWDL/P2P
 * selectors stay unsupported rather than pretending a radio operation completed.
 */
#include "AirPortRTW.hpp"
#include "AirPortRTWInterface.hpp"
#include "RTW88TxDrainGuard.hpp"
#include <net/bpf.h>
#include <sys/kpi_mbuf.h>

#define super IO80211Controller

static const char *rtw88VifRoleName(UInt role)
{
    return role == APPLE80211_VIF_AWDL ? "awdl" : "p2p";
}

struct RTW88MdnsInfo {
    bool ipv6 = false;
    bool mdns = false;
    bool response = false;
    bool airDrop = false;
    bool serviceIdValid = false;
    uint8_t serviceId[12] = {};
};

static bool rtw88HexAscii(uint8_t c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static RTW88MdnsInfo rtw88InspectAWDLMdnsPacket(mbuf_t m)
{
    RTW88MdnsInfo info;
    if (!m || mbuf_pkthdr_len(m) < 62) return info;

    uint8_t bytes[768] = {};
    const size_t total = mbuf_pkthdr_len(m);
    const size_t copy = total < sizeof(bytes) ? total : sizeof(bytes);
    if (mbuf_copydata(m, 0, copy, bytes) != 0) return info;

    const uint16_t type = (uint16_t(uint16_t(bytes[12]) << 8) | bytes[13]);
    if (type != 0x86dd || copy < 54) return info;
    info.ipv6 = true;
    if (bytes[20] != 17 || copy < 62) return info; /* IPv6 next-header UDP */

    const uint8_t *udp = bytes + 54;
    const uint16_t sport = (uint16_t(uint16_t(udp[0]) << 8) | udp[1]);
    const uint16_t dport = (uint16_t(uint16_t(udp[2]) << 8) | udp[3]);
    if (sport != 5353 && dport != 5353) return info;
    info.mdns = true;

    const size_t dns = 62;
    if (copy >= dns + 12)
        info.response = (bytes[dns + 2] & 0x80U) != 0;

    static const uint8_t needle[] = {'_','a','i','r','d','r','o','p'};
    for (size_t i = dns; i + sizeof(needle) <= copy; ++i) {
        if (!memcmp(bytes + i, needle, sizeof(needle))) {
            info.airDrop = true;
            break;
        }
    }

    /* Apple/sharingd uses a 12-hex-character AirDrop service instance ID.
     * Capture it only from a packet that explicitly contains "_airdrop", so
     * unrelated Bonjour UUIDs cannot seed the native MIF Service Response. */
    if (info.airDrop) {
        for (size_t i = dns; i + 13 <= copy; ++i) {
            if (bytes[i] != 12) continue;
            bool hex = true;
            for (unsigned j = 0; j < 12; ++j)
                hex = hex && rtw88HexAscii(bytes[i + 1 + j]);
            if (hex) {
                memcpy(info.serviceId, bytes + i + 1, 12);
                info.serviceIdValid = true;
                break;
            }
        }
    }
    return info;
}

void AirPortRTW::traceAWDLTxPacket(mbuf_t m, unsigned path)
{
    if (!m || path >= 3) return;
    __atomic_fetch_add(&_awdlTxPathCalls[path], 1U, __ATOMIC_RELAXED);
    const size_t length = mbuf_pkthdr_len(m);
    if (path == 0)
        __atomic_store_n(&_awdlTxLastPacketLength,
                         (uint32_t)(length > UINT32_MAX ? UINT32_MAX : length),
                         __ATOMIC_RELAXED);
    if (length < 14) return;

    /* Only Ethernet/IPv6/UDP metadata is retained. Normal controller traffic
     * needs a 14-byte read; the bounded DNS scan runs only for mDNS. Calls on
     * the controller path may include output-queue retries, not unique TX. */
    uint8_t header[62] = {};
    if (mbuf_copydata(m, 0, 14, header) != 0) {
        __atomic_fetch_add(&_awdlTxTraceCopyErrors, 1U, __ATOMIC_RELAXED);
        return;
    }
    const uint16_t type = (uint16_t(header[12]) << 8) | header[13];
    if (path == 0) {
        __atomic_store_n(&_awdlTxLastEtherType, (uint32_t)type, __ATOMIC_RELAXED);
        __atomic_store_n(&_awdlTxLastIPv6NextHeader, 0U, __ATOMIC_RELAXED);
    }
    if (type != 0x86dd || length < sizeof(header)) return;
    if (mbuf_copydata(m, 14, sizeof(header) - 14, header + 14) != 0) {
        __atomic_fetch_add(&_awdlTxTraceCopyErrors, 1U, __ATOMIC_RELAXED);
        return;
    }
    if (path == 0)
        __atomic_store_n(&_awdlTxLastIPv6NextHeader, (uint32_t)header[20], __ATOMIC_RELAXED);
    if (header[20] != 17) return;
    const uint16_t sport = (uint16_t(header[54]) << 8) | header[55];
    const uint16_t dport = (uint16_t(header[56]) << 8) | header[57];
    if (sport != 5353 && dport != 5353) return;
    const RTW88MdnsInfo info = rtw88InspectAWDLMdnsPacket(m);
    if (info.mdns) __atomic_fetch_add(&_awdlTxPathMdns[path], 1U, __ATOMIC_RELAXED);
    if (info.airDrop) __atomic_fetch_add(&_awdlTxPathAirDrop[path], 1U, __ATOMIC_RELAXED);
    if (info.serviceIdValid) __atomic_fetch_add(&_awdlTxPathServiceId[path], 1U, __ATOMIC_RELAXED);
    if (info.mdns) {
        __atomic_fetch_add(info.response ? &_awdlTxPathResponses[path] : &_awdlTxPathQueries[path],
                           1U, __ATOMIC_RELAXED);
        if (path == 1) {
            uint64_t src = 0;
            for (unsigned i = 6; i < 12; ++i) src = (src << 8) | header[i];
            const uint64_t local = __atomic_load_n(&_awdlTxLocalMac, __ATOMIC_RELAXED);
            const bool awdlSource = local && src == local;
            __atomic_fetch_add(awdlSource ? &_awdlTxControllerAWDLSource : &_awdlTxControllerOtherSource,
                               1U, __ATOMIC_RELAXED);
            if (awdlSource && info.airDrop)
                __atomic_fetch_add(&_awdlTxControllerAWDLAirDrop, 1U, __ATOMIC_RELAXED);
            __atomic_store_n(&_awdlTxControllerLastSource, src, __ATOMIC_RELAXED);
        }
    }
}

void AirPortRTW::publishAWDLTxDiagnostics()
{
    /* Called by the existing five-second diagnostics timer. No registry
     * allocation or packet logging is added to the high-frequency hooks. */
    __atomic_fetch_add(&_awdlTxDiagnosticSamples, 1U, __ATOMIC_RELAXED);
    struct Counter { const char *name; const uint32_t *value; };
    const Counter counters[] = {
        {"AWDL_TX_DIAGNOSTIC_SAMPLES", &_awdlTxDiagnosticSamples},
        {"AWDL_TX_REJECTED_POWER", &_awdlTxRejectedPower},
        {"AWDL_VIF_ENABLE_CALLS", &_awdlVifEnableCalls},
        {"AWDL_VIF_DISABLE_CALLS", &_awdlVifDisableCalls},
        {"AWDL_VIF_ENABLE_RAW", &_awdlVifEnableResult},
        {"AWDL_VIF_DISABLE_RAW", &_awdlVifDisableResult},
        {"AWDL_VIF_ENABLED_OBSERVED", &_awdlVifEnabledObserved},
        {"AWDL_TX_REENTRANT_SKIPPED", &_awdlTxReentrantSkipped},
        {"AWDL_TX_OUTPUT_START_STA", &_awdlTxOutputStartSTA},
        {"AWDL_TX_OUTPUT_START_OTHER", &_awdlTxOutputStartOther},
        {"AWDL_TX_PARAM_VIF_MATCH", &_awdlTxParamVifMatch},
        {"AWDL_TX_PARAM_STA_MATCH", &_awdlTxParamStaMatch},
        {"AWDL_TX_PARAM_NULL", &_awdlTxParamNull},
        {"AWDL_TX_PARAM_OTHER", &_awdlTxParamOther},
        {"AWDL_TX_CONTROLLER_MDNS_AWDL_SOURCE", &_awdlTxControllerAWDLSource},
        {"AWDL_TX_CONTROLLER_MDNS_OTHER_SOURCE", &_awdlTxControllerOtherSource},
        {"AWDL_TX_CONTROLLER_AIRDROP_AWDL_SOURCE", &_awdlTxControllerAWDLAirDrop},
        {"AWDL_TX_DEQUEUE_MDNS_QUERIES", &_awdlTxPathQueries[0]},
        {"AWDL_TX_DEQUEUE_MDNS_RESPONSES", &_awdlTxPathResponses[0]},
        {"AWDL_TX_CONTROLLER_MDNS_QUERIES", &_awdlTxPathQueries[1]},
        {"AWDL_TX_CONTROLLER_MDNS_RESPONSES", &_awdlTxPathResponses[1]},
        {"AWDL_TX_BPF_MDNS_QUERIES", &_awdlTxPathQueries[2]},
        {"AWDL_TX_BPF_MDNS_RESPONSES", &_awdlTxPathResponses[2]},
        {"AWDL_TX_SYSTEM_CALLBACKS", &_awdlTxSystemCallbacks},
        {"AWDL_TX_TIMER_POLLS", &_awdlTxTimerPolls},
        {"AWDL_TX_REJECTED_DMA", &_awdlTxRejectedDma},
        {"AWDL_TX_REJECTED_OBJECT", &_awdlTxRejectedObject},
        {"AWDL_TX_LAST_OPTIONS", &_awdlTxLastOptions},
        {"AWDL_TX_DEQUEUE_BOOL_TRUE", &_awdlTxDequeueTrue},
        {"AWDL_TX_DEQUEUE_BOOL_FALSE", &_awdlTxDequeueFalse},
        {"AWDL_TX_DEQUEUE_TRUE_EMPTY", &_awdlTxDequeueTrueEmpty},
        {"AWDL_TX_DEQUEUE_FALSE_WITH_HEAD", &_awdlTxDequeueFalseWithHead},
        {"AWDL_TX_ACTUAL_DEQUEUED", &_awdlTxActualDequeued},
        {"AWDL_TX_DEQUEUE_COUNT_MISMATCH", &_awdlTxDequeueCountMismatch},
        {"AWDL_TX_DEQUEUE_PATH_CALLS", &_awdlTxPathCalls[0]},
        {"AWDL_TX_DEQUEUE_PATH_MDNS", &_awdlTxPathMdns[0]},
        {"AWDL_TX_DEQUEUE_PATH_AIRDROP", &_awdlTxPathAirDrop[0]},
        {"AWDL_TX_DEQUEUE_PATH_SERVICE_ID", &_awdlTxPathServiceId[0]},
        {"AWDL_TX_CONTROLLER_PATH_CALLS", &_awdlTxPathCalls[1]},
        {"AWDL_TX_CONTROLLER_PATH_MDNS", &_awdlTxPathMdns[1]},
        {"AWDL_TX_CONTROLLER_PATH_AIRDROP", &_awdlTxPathAirDrop[1]},
        {"AWDL_TX_CONTROLLER_PATH_SERVICE_ID", &_awdlTxPathServiceId[1]},
        {"AWDL_TX_BPF_ETHERNET_CALLS", &_awdlTxPathCalls[2]},
        {"AWDL_TX_BPF_ETHERNET_MDNS", &_awdlTxPathMdns[2]},
        {"AWDL_TX_BPF_ETHERNET_AIRDROP", &_awdlTxPathAirDrop[2]},
        {"AWDL_TX_BPF_ETHERNET_SERVICE_ID", &_awdlTxPathServiceId[2]},
        {"AWDL_TX_BPF_CALLS", &_awdlTxBpfCalls},
        {"AWDL_TX_BPF_LAST_DLT", &_awdlTxBpfLastDlt},
        {"AWDL_TX_TRACE_COPY_ERRORS", &_awdlTxTraceCopyErrors},
        {"AWDL_TX_LAST_PACKET_LENGTH", &_awdlTxLastPacketLength},
        {"AWDL_TX_LAST_ETHERTYPE", &_awdlTxLastEtherType},
        {"AWDL_TX_LAST_IPV6_NEXT_HEADER", &_awdlTxLastIPv6NextHeader}
    };
    for (const auto &counter : counters)
        setProperty(counter.name, (uint64_t)__atomic_load_n(counter.value, __ATOMIC_RELAXED), 32);
    setProperty("AWDL_TX_LOCAL_MAC_PACKED", __atomic_load_n(&_awdlTxLocalMac, __ATOMIC_RELAXED), 64);
    setProperty("AWDL_TX_CONTROLLER_LAST_SOURCE_PACKED", __atomic_load_n(&_awdlTxControllerLastSource, __ATOMIC_RELAXED), 64);

    static const char *trueNames[] = {
        "AWDL_TX_CLASS_CTL_TRUE", "AWDL_TX_CLASS_VO_TRUE", "AWDL_TX_CLASS_VI_TRUE",
        "AWDL_TX_CLASS_RV_TRUE", "AWDL_TX_CLASS_AV_TRUE", "AWDL_TX_CLASS_OAM_TRUE",
        "AWDL_TX_CLASS_RD_TRUE", "AWDL_TX_CLASS_BE_TRUE", "AWDL_TX_CLASS_BK_TRUE",
        "AWDL_TX_CLASS_BKSYS_TRUE"
    };
    static const char *falseNames[] = {
        "AWDL_TX_CLASS_CTL_FALSE", "AWDL_TX_CLASS_VO_FALSE", "AWDL_TX_CLASS_VI_FALSE",
        "AWDL_TX_CLASS_RV_FALSE", "AWDL_TX_CLASS_AV_FALSE", "AWDL_TX_CLASS_OAM_FALSE",
        "AWDL_TX_CLASS_RD_FALSE", "AWDL_TX_CLASS_BE_FALSE", "AWDL_TX_CLASS_BK_FALSE",
        "AWDL_TX_CLASS_BKSYS_FALSE"
    };
    static_assert(sizeof(trueNames) / sizeof(trueNames[0]) == 10, "TX class diagnostics");
    static_assert(sizeof(falseNames) == sizeof(trueNames), "TX class diagnostics");
    for (unsigned i = 0; i < 10; ++i) {
        setProperty(trueNames[i], (uint64_t)__atomic_load_n(&_awdlTxClassTrue[i], __ATOMIC_RELAXED), 32);
        setProperty(falseNames[i], (uint64_t)__atomic_load_n(&_awdlTxClassFalse[i], __ATOMIC_RELAXED), 32);
    }
    setProperty("AWDL_TX_DIAGNOSTIC_MODE", "passive-handoff");
}

static uint16_t rtw88PreferredAWDLSocialChannel(RTW88IEEE80211 *backend)
{
    if (!backend) return 0;
    RTW88Channel channels[APPLE80211_MAX_CHANNELS] = {};
    uint32_t count = 0;
    IOReturn ret = backend->copyChannels(channels, APPLE80211_MAX_CHANNELS, &count);
    if (ret != kIOReturnSuccess && ret != kIOReturnNoSpace) return 0;

    bool ch6 = false, ch44 = false, ch149 = false;
    for (uint32_t i = 0; i < count && i < APPLE80211_MAX_CHANNELS; ++i) {
        if (channels[i].number == 6) ch6 = true;
        else if (channels[i].number == 44) ch44 = true;
        else if (channels[i].number == 149) ch149 = true;
    }

    /* Apple hardware normally prefers a 5 GHz AWDL social channel when the
     * current regulatory channel table permits it.  Choosing only from the
     * driver's validated channel list keeps this safe across regions: 149 is
     * used where legal, otherwise 44, then 2.4 GHz channel 6. */
    if (ch149) return 149;
    if (ch44) return 44;
    if (ch6) return 6;
    return count ? channels[0].number : 0;
}

IO80211VirtualInterface *AirPortRTW::createVirtualInterface(ether_addr *addr, UInt role)
{
    IOLog("AirPortRTW: createVirtualInterface role=%u\n", role);

    if (role < APPLE80211_VIF_P2P_DEVICE || role > APPLE80211_VIF_AWDL)
        return super::createVirtualInterface(addr, role);

    /* IO80211's peer-to-peer roles (including AWDL/AirLink) must be backed by
     * IO80211P2PInterface, not a bare IO80211VirtualInterface.  A bare VIF is
     * sufficient to allocate/publish an ifnet named awdl0, but Ventura does
     * not classify it as a peer-to-peer virtual interface: the result is the
     * exact ghost state we observed (BSD awdl0 exists, MTU 0/inactive, while
     * Apple80211GetVirtualIfListCopy reports zero interfaces).
     *
     * Real IO80211 traces show AWDL role 4 running both
     * IO80211VirtualInterface::init and IO80211P2PInterface::init.  Construct
     * the derived class so its virtual init performs the P2P/AWDL setup. */
    IO80211P2PInterface *p2p = new IO80211P2PInterface;
    if (!p2p)
        return nullptr;

    if (!p2p->init(this, addr, role, rtw88VifRoleName(role))) {
        IOLog("AirPortRTW: P2P virtual interface init failed role=%u\n", role);
        p2p->release();
        return nullptr;
    }

    IO80211VirtualInterface *interface = p2p;
    if (role == APPLE80211_VIF_AWDL && _awdlManager && addr) {
        _awdlManager->setLocalAddress(addr->octet);
        uint64_t mac = 0;
        for (unsigned i = 0; i < 6; ++i) mac = (mac << 8) | addr->octet[i];
        __atomic_store_n(&_awdlTxLocalMac, mac, __ATOMIC_RELAXED);
    }
    IOLog("AirPortRTW: P2P virtual interface created role=%u name=%s class=%s\n",
          role, rtw88VifRoleName(role), interface->getMetaClass()->getClassName());
    return interface;
}

SInt32 AirPortRTW::enableVirtualInterface(IO80211VirtualInterface *interface)
{
    if (!interface)
        return kIOReturnBadArgument;
    __atomic_fetch_add(&_awdlVifEnableCalls, 1U, __ATOMIC_RELAXED);
    if (__atomic_load_n(&_shutdown, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&_pmTransition, __ATOMIC_ACQUIRE) ||
        _pmPowerState == kRTW88PowerStateOff)
        return kIOReturnNotReady;

    UInt role = (UInt)interface->getInterfaceRole();
    IOLog("AirPortRTW: enableVirtualInterface role=%u bsd=%s\n",
          role, interface->getBSDName() ? interface->getBSDName() : "?");

    SInt32 ret = super::enableVirtualInterface(interface);
    __atomic_store_n(&_awdlVifEnableResult, (uint32_t)ret, __ATOMIC_RELAXED);
    if (ret != kIOReturnSuccess)
        return ret;

    if (_awdlManager)
        _awdlManager->setVirtualInterface(role, interface);
    if (role == APPLE80211_VIF_AWDL && _ieee80211) {
        /* A real Apple controller exposes a concrete AirDrop/AWDL channel to
         * IO80211/System Information even before a peer has been elected.
         * If IO80211 has not supplied one yet, seed the manager from the
         * regulatory channel table instead of leaving MASTER_CHANNEL at 0. */
        if (_awdlManager && !_awdlManager->masterChannel()) {
            uint16_t social = rtw88PreferredAWDLSocialChannel(_ieee80211);
            if (social) _awdlManager->setMasterChannel(social);
        }
        (void)_ieee80211->setAWDLReceiveMode(true);
    }

#if __IO80211_TARGET >= __MAC_13_0
    interface->setEnabledBySystem(true);
#endif
    interface->setLinkState(kIO80211NetworkLinkUp, 0);
    interface->postMessage(APPLE80211_M_LINK_CHANGED);
    __atomic_store_n(&_awdlVifEnabledObserved, 1U, __ATOMIC_RELAXED);
    if (role == APPLE80211_VIF_AWDL && _awdlManager && _ieee80211 && _ieee80211->isPowered())
        _awdlManager->resumeAfterPowerTransition();
    return kIOReturnSuccess;
}

SInt32 AirPortRTW::disableVirtualInterface(IO80211VirtualInterface *interface)
{
    if (!interface)
        return kIOReturnBadArgument;

    UInt role = (UInt)interface->getInterfaceRole();
    IOLog("AirPortRTW: disableVirtualInterface role=%u bsd=%s\n",
          role, interface->getBSDName() ? interface->getBSDName() : "?");

    __atomic_fetch_add(&_awdlVifDisableCalls, 1U, __ATOMIC_RELAXED);
    /* Match the reference IO80211 driver: let IO80211 tear the VIF down first, then publish
     * link-down only after the superclass accepted the transition. */
    SInt32 ret = super::disableVirtualInterface(interface);
    __atomic_store_n(&_awdlVifDisableResult, (uint32_t)ret, __ATOMIC_RELAXED);
    if (ret != kIOReturnSuccess)
        return ret;

    __atomic_store_n(&_awdlVifEnabledObserved, 0U, __ATOMIC_RELAXED);
    interface->setLinkState(kIO80211NetworkLinkDown, 0);
    interface->postMessage(APPLE80211_M_LINK_CHANGED);
    if (role == APPLE80211_VIF_AWDL && _ieee80211)
        (void)_ieee80211->setAWDLReceiveMode(false);
    if (_awdlManager)
        _awdlManager->clearVirtualInterface(interface);
    return kIOReturnSuccess;
}

SInt32 AirPortRTW::apple80211VirtualRequest(UInt request_type, int request_number,
                                               IO80211VirtualInterface *interface,
                                               void *data)
{
    // Bounded registry status, no per-request console trace or payload dump.
    setProperty("AWDL_CONTROL_SEEN", kOSBooleanTrue);
    setProperty("AWDL_CONTROL_SELECTOR", (uint64_t)(uint32_t)request_number, 32);
    if (request_number == APPLE80211_IOC_AWDL_SYNC_FRAME_TEMPLATE)
        setProperty("AWDL_TEMPLATE_REQUEST_SEEN", kOSBooleanTrue);
    SInt32 result = handleAWDLVirtualRequest(request_type, request_number, interface, data);
    if (result != kIOReturnSuccess) {
        setProperty("AWDL_CONTROL_ERROR_SELECTOR", (uint64_t)(uint32_t)request_number, 32);
        setProperty("AWDL_CONTROL_ERROR", (uint64_t)(uint32_t)result, 32);
    }
    return result;
}

SInt32 AirPortRTW::handleAWDLVirtualRequest(UInt request_type, int request_number,
                                               IO80211VirtualInterface *interface,
                                               void *data)
{
    if (request_type != SIOCGA80211 && request_type != SIOCSA80211)
        return kIOReturnBadArgument;
    bool set = request_type == SIOCSA80211;
    UInt role = interface ? (UInt)interface->getInterfaceRole() : 0;

    /* Mirror the reference IO80211 driver's architecture: IO80211 owns AWDL policy and the
     * driver acts as its control-plane adapter. Keep a bounded record of which
     * Apple selectors have arrived; the Realtek scheduler alone owns physical
     * channel changes on the single PHY. */
    if (set && role == APPLE80211_VIF_AWDL && _awdlManager) {
        uint32_t bit = 0;
        switch (request_number) {
        case APPLE80211_IOC_AWDL_SYNC_ENABLED: bit = RTW88AWDLManager::kAppleCtlSyncEnabled; break;
        case APPLE80211_IOC_AWDL_SYNC_FRAME_TEMPLATE: bit = RTW88AWDLManager::kAppleCtlTemplate; break;
        case APPLE80211_IOC_CHANNEL:
        case APPLE80211_IOC_AWDL_MASTER_CHANNEL: bit = RTW88AWDLManager::kAppleCtlMasterChannel; break;
        case APPLE80211_IOC_AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE: bit = RTW88AWDLManager::kAppleCtlChannelSequence; break;
        case APPLE80211_IOC_AWDL_SYNC_PARAMS: bit = RTW88AWDLManager::kAppleCtlSyncParams; break;
        case APPLE80211_IOC_AWDL_PRESENCE_MODE: bit = RTW88AWDLManager::kAppleCtlPresence; break;
        case APPLE80211_IOC_AWDL_SYNC_STATE: bit = RTW88AWDLManager::kAppleCtlSyncState; break;
        case APPLE80211_IOC_AWDL_ELECTION_METRIC:
        case APPLE80211_IOC_AWDL_ELECTION_ID: bit = RTW88AWDLManager::kAppleCtlElection; break;
        default: break;
        }
        if (bit) _awdlManager->noteAppleControl(bit);
    }

    /* Common control-plane selectors describe the same physical radio. */
    switch (request_number) {
    case APPLE80211_IOC_CARD_CAPABILITIES:
    case APPLE80211_IOC_POWER:
    case APPLE80211_IOC_SUPPORTED_CHANNELS:
    case APPLE80211_IOC_DRIVER_VERSION:
    case APPLE80211_IOC_OP_MODE:
    case APPLE80211_IOC_PHY_MODE:
    case APPLE80211_IOC_RSSI:
    case APPLE80211_IOC_COUNTRY_CODE:
        /* awdl0 shares the same physical regulatory domain as en0.
         * Forward COUNTRY_CODE through the infrastructure handler so GET
         * returns the controller's current _countryCode and Apple's special
         * XZ/xZ SET requests are acknowledged without replacing it. */
        return apple80211Request(request_type, request_number, _netif, data);

    case APPLE80211_IOC_STATE:
    case APPLE80211_IOC_BSSID:
    case APPLE80211_IOC_AUTH_TYPE: {
        if (role != APPLE80211_VIF_AWDL)
            return apple80211Request(request_type, request_number, _netif, data);
        if (!data) return kIOReturnBadArgument;
        if (set) return kIOReturnUnsupported;
        if (!_awdlManager) return kIOReturnNotReady;
        if (request_number == APPLE80211_IOC_STATE) {
            auto *d = static_cast<apple80211_state_data *>(data);
            bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION;
            // VIF lifecycle state, not proof of peer discovery or delivery.
            d->state = _awdlManager->awdlInterface() == interface && _awdlManager->syncEnabled()
                ? APPLE80211_S_RUN : APPLE80211_S_INIT;
        } else if (request_number == APPLE80211_IOC_BSSID) {
            auto *d = static_cast<apple80211_bssid_data *>(data);
            bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION;
            _awdlManager->getBSSID(d->bssid.octet);
        } else {
            auto *d = static_cast<apple80211_authtype_data *>(data);
            bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION;
            d->authtype_lower = APPLE80211_AUTHTYPE_OPEN;
            d->authtype_upper = APPLE80211_AUTHTYPE_NONE;
        }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_SSID: {
        if (role != APPLE80211_VIF_AWDL)
            return apple80211Request(request_type, request_number, _netif, data);
        if (!data) return kIOReturnBadArgument;
        if (set) return kIOReturnUnsupported;
        // AWDL has no infrastructure SSID. A startup query must not inherit
        // STA's ENXIO before association, nor expose the AP's SSID afterward.
        auto *d = static_cast<apple80211_ssid_data *>(data);
        bzero(d, sizeof(*d));
        d->version = APPLE80211_VERSION;
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_CHANNEL: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_channel_data *)data;
        if (role != APPLE80211_VIF_AWDL)
            return apple80211Request(request_type, request_number, _netif, data);
        if (set) {
            if (d->version != APPLE80211_VERSION || d->channel.channel == 0)
                return kIOReturnBadArgument;
            if (!_awdlManager) return kIOReturnNotReady;
            _awdlManager->setMasterChannel(d->channel.channel);
            /* Do not retune here. IO80211 may issue this while en0 is on its
             * AP channel; the availability-window scheduler performs the
             * actual Realtek channel switch at a safe instant. */
            return kIOReturnSuccess;
        }
        uint16_t ch = _awdlManager ? (uint16_t)_awdlManager->reportedChannel() : 0;
        if (!ch) return kIOReturnNotReady;
        bzero(d, sizeof(*d));
        d->version = APPLE80211_VERSION;
        d->channel.version = APPLE80211_VERSION;
        d->channel.channel = ch;
        d->channel.flags = APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_20MHZ |
            (ch <= 14 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ);
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_SYNC_ENABLED: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_awdl_sync_enabled *)data;
        if (set) {
            if (!_awdlManager) return kIOReturnNotReady;
            _awdlManager->setSyncEnabled(d->enabled != 0);
            IOLog("AirPortRTW: AWDL sync enabled=%d\n", _awdlManager->syncEnabled());
        } else {
            bzero(d, sizeof(*d));
            d->version = APPLE80211_VERSION;
            d->enabled = (_awdlManager && _awdlManager->syncEnabled()) ? 1 : 0;
        }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_ELECTION_METRIC: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_awdl_election_metric *)data;
        if (set) {
            if (!_awdlManager) return kIOReturnNotReady;
            _awdlManager->setElectionMetric(d->metric);
        } else {
            bzero(d, sizeof(*d));
            d->version = APPLE80211_VERSION;
            d->metric = _awdlManager ? _awdlManager->electionMetric() : 0;
        }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_PEER_TRAFFIC_REGISTRATION: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_awdl_peer_traffic_registration *)data;
        if (!set)
            return kIOReturnNotFound;
        uint32_t n = d->name_len < sizeof(d->name) ? d->name_len : (uint32_t)sizeof(d->name);
        if (_awdlManager)
            _awdlManager->notePeerTrafficRegistration(d->active != 0,
                                                      (const char *)d->name,
                                                      n);
        IOLog("AirPortRTW: AWDL peer traffic registration active=%u name_len=%u peers=%u\n",
              d->active, n, _awdlManager ? _awdlManager->peerRegistrationCount() : 0);
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_SYNC_FRAME_TEMPLATE: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_awdl_sync_frame_template *)data;
        if (!_awdlManager) return kIOReturnNotReady;
        if (set) {
            IOReturn ret = _awdlManager->setSyncFrameTemplate(d->payload, d->payload_len);
            if (ret == kIOReturnSuccess)
                IOLog("AirPortRTW: AWDL sync template len=%u\n", d->payload_len);
            return ret;
        }
        if (!d->payload) return kIOReturnBadArgument;
        uint32_t length = d->payload_len;
        IOReturn ret = _awdlManager->copySyncFrameTemplate(d->payload, &length);
        /* Always publish the required/actual size, including kIOReturnNoSpace,
         * so IO80211 can retry with an adequate buffer. */
        d->version = APPLE80211_VERSION;
        d->payload_len = length;
        if (ret) return ret;
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_HT_CAPABILITY: {
        if (set || !data) return kIOReturnUnsupported;
        auto *d = (apple80211_ht_capability *)data;
        bzero(d, sizeof(*d));
        d->version = APPLE80211_VERSION;
        /* The reference IO80211 driver master: element 45 + CBW20/40 + SGI20 + SGI40.
         * The pinned header names these fields unk1/unk3 but the bundled
         * the reference IO80211 driver fixture confirms their exact offsets. */
        d->unk1 = 45;
        d->unk3 = 0x0062;
        IOLog("AirPortRTW: AWDL HT_CAPABILITY cap=0x%x\n", d->unk3);
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_VHT_CAPABILITY: {
        if (set || !data) return kIOReturnUnsupported;
        auto *d = (apple80211_vht_capability *)data;
        bzero(d, sizeof(*d));
        d->version = APPLE80211_VERSION;
        d->cap = 3263; /* Match the reference IO80211 driver's Ventura legacy path. */
        IOLog("AirPortRTW: AWDL VHT_CAPABILITY cap=%u\n", d->cap);
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_CHANNELS_INFO: {
        if (set || !data || !_ieee80211) return kIOReturnUnsupported;
        auto *d = (apple80211_channels_info *)data;
        bzero(d, sizeof(*d));
        d->version = APPLE80211_VERSION;
        RTW88Channel channels[APPLE80211_MAX_CHANNELS] = {};
        uint32_t count = 0;
        IOReturn ret = _ieee80211->copyChannels(channels, APPLE80211_MAX_CHANNELS, &count);
        if (ret != kIOReturnSuccess && ret != kIOReturnNoSpace) return ret;
        if (count > APPLE80211_MAX_CHANNELS) count = APPLE80211_MAX_CHANNELS;
        for (uint32_t i = 0; i < count; ++i) {
            const uint16_t ch = channels[i].number;
            d->chan_num[i] = (uint8_t)ch;
            d->passive[i] = channels[i].passive ? 1 : 0;
            d->radar_dfs[i] = channels[i].radar ? 1 : 0;
            /* RTL8822B supports HT40 and VHT80. Keep width claims limited to
             * bands where the physical radio can actually use them. */
            d->support_40Mhz[i] = (ch != 14) ? 1 : 0;
            d->support_80Mhz[i] = (ch > 14) ? 1 : 0;
            d->chan_spec[i] = ch;
        }
        d->num_chan_specs = (uint16_t)count;
        IOLog("AirPortRTW: AWDL CHANNELS_INFO count=%u\n", count);
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_PEER_CACHE_MAXIMUM_SIZE: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_peer_cache_maximum_size *)data;
        if (set) {
            IOLog("AirPortRTW: AWDL peer cache max requested=%u\n", d->max_peers);
            return kIOReturnSuccess;
        }
        bzero(d, sizeof(*d));
        d->version = APPLE80211_VERSION;
        d->max_peers = 255;
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_P2P_ENABLE:
        if (!set) return kIOReturnUnsupported;
        if (_awdlManager) _awdlManager->setP2PEnabled(true);
        IOLog("AirPortRTW: P2P_ENABLE accepted (Ventura opaque ABI)\n");
        return kIOReturnSuccess;

    case APPLE80211_IOC_P2P_SCAN: {
        /* The reference IO80211 driver accepts/logs this as part of virtual-interface service
         * initialization. Use Ventura's published apple80211_scan_data ABI,
         * but do not start a second concurrent STA scan from the VIF path. */
        if (!set || !data) return kIOReturnUnsupported;
        auto *d = (apple80211_scan_data *)data;
        if (d->version != APPLE80211_VERSION ||
            d->ssid_len > APPLE80211_MAX_SSID_LEN ||
            d->num_channels > APPLE80211_MAX_CHANNELS)
            return kIOReturnBadArgument;
        IOLog("AirPortRTW: P2P_SCAN ssid_len=%u channels=%u type=%u phy=0x%x\n",
              d->ssid_len, d->num_channels, d->scan_type, d->phy_mode);
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_P2P_LISTEN:
        /* The reference IO80211 driver accepts this request. The pinned Ventura SDK does not
         * publish apple80211_p2p_listen_data, so keep the payload opaque. */
        if (!set) return kIOReturnUnsupported;
        IOLog("AirPortRTW: P2P_LISTEN accepted (opaque Ventura ABI)\n");
        return kIOReturnSuccess;

    case APPLE80211_IOC_P2P_GO_CONF:
        if (!set) return kIOReturnUnsupported;
        IOLog("AirPortRTW: P2P_GO_CONF accepted (opaque Ventura ABI)\n");
        return kIOReturnSuccess;

    case APPLE80211_IOC_AWDL_BSSID: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_bssid *)data;
        if (set) _awdlManager->setBSSID(d->bssid);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; _awdlManager->getBSSID(d->bssid); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_ELECTION_ID: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_election_id *)data;
        if (set) _awdlManager->setElectionId(d->election_id);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->election_id = _awdlManager->electionId(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_MASTER_CHANNEL: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_master_channel *)data;
        if (set) {
            if (!d->master_channel) return kIOReturnBadArgument;
            _awdlManager->setMasterChannel(d->master_channel);
        } else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->master_channel = _awdlManager->reportedMasterChannel(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_SECONDARY_MASTER_CHANNEL: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_secondary_master_channel *)data;
        if (set) _awdlManager->setSecondaryMasterChannel(d->secondary_master_channel);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->secondary_master_channel = _awdlManager->secondaryMasterChannel(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_MIN_RATE: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_min_rate *)data;
        if (set) _awdlManager->setMinRate(d->min_rate);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->min_rate = _awdlManager->minRate(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_ELECTION_RSSI_THRESHOLDS: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_awdl_election_rssi_thresholds *)data;
        if (!set) { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_sync_channel_sequence *)data;
        if (set) {
            IOReturn r = _awdlManager->setSyncChannelSequence(d, sizeof(*d));
            if (r != kIOReturnSuccess) return r;
            IOLog("AirPortRTW: AWDL sync channel sequence len=%u enc=%u steps=%u dup=%u fill_ch=%u\n",
                  (unsigned)d->length, (unsigned)d->encoding, (unsigned)d->step_count,
                  (unsigned)d->duplicate_count, (unsigned)d->fill_channel);
            /* Store the Apple sequence exactly. The Realtek PHY is deliberately
             * not retuned from an IOCTL callback; tick() applies the schedule
             * while respecting the infrastructure STA's home channel. */
        } else {
            bzero(d, sizeof(*d));
            IOReturn r = _awdlManager->copySyncChannelSequence(d, sizeof(*d));
            if (r != kIOReturnSuccess) {
                d->version = APPLE80211_VERSION;
                return kIOReturnSuccess;
            }
        }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_PRESENCE_MODE: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_presence_mode *)data;
        if (set) _awdlManager->setPresenceMode(d->mode);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->mode = _awdlManager->presenceMode(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_EXTENSION_STATE_MACHINE_PARAMETERS: {
        if (!data) return kIOReturnBadArgument;
        auto *d = (apple80211_awdl_extension_state_machine_parameter *)data;
        if (!set) { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_SYNC_STATE: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_sync_state *)data;
        if (set) _awdlManager->setSyncState(d->state);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->state = _awdlManager->syncState(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_SYNC_PARAMS: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_sync_params *)data;
        if (set) {
            _awdlManager->setSyncParams(d->availability_window_length,
                                        d->availability_window_period,
                                        d->extension_length,
                                        d->synchronization_frame_period);
            IOLog("AirPortRTW: AWDL sync params aw_len=%u aw_period=%u ext=%u sync_period=%u\n",
                  d->availability_window_length, d->availability_window_period,
                  d->extension_length, d->synchronization_frame_period);
        } else {
            bzero(d, sizeof(*d));
            d->version = APPLE80211_VERSION;
            if (_awdlManager->syncParamsValid()) {
                d->availability_window_length = _awdlManager->availabilityWindowLength();
                d->availability_window_period = _awdlManager->availabilityWindowPeriod();
                d->extension_length = _awdlManager->extensionLength();
                d->synchronization_frame_period = _awdlManager->synchronizationFramePeriod();
            }
        }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_DEVICE_CAPABILITIES: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_cap *)data;
        if (set) _awdlManager->setDeviceCapabilities(d->cap);
        else {
            bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION;
            /* The reference IO80211 driver reports CCA-stats capability. Its public fixture
             * uses bit 0 for this legacy capability. */
            d->cap = _awdlManager->deviceCapabilities();
            if (!d->cap) d->cap = 1;
        }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_AF_TX_MODE: {
        if (!data || !_awdlManager) return kIOReturnNotReady;
        auto *d = (apple80211_awdl_af_tx_mode *)data;
        if (set) _awdlManager->setActionFrameTxMode(d->mode);
        else { bzero(d, sizeof(*d)); d->version = APPLE80211_VERSION; d->mode = _awdlManager->actionFrameTxMode(); }
        return kIOReturnSuccess;
    }

    case APPLE80211_IOC_AWDL_OOB_AUTO_REQUEST:
        /* The reference IO80211 driver only consumes this as a SET. The large private OOB
         * payload is not needed for basic AWDL transport bring-up. */
        return set ? kIOReturnSuccess : kIOReturnUnsupported;

    default:
        break;
    }

    IOLog("AirPortRTW: VIF selector=%d unsupported (ABI/transport not implemented)\n",
          request_number);
    return kIOReturnUnsupported;
}

static int rtw88SendActionFrame(RTW88IEEE80211 *backend, mbuf_t m)
{
    if (!m) return kIOReturnBadArgument;
    if (!backend) { mbuf_freem(m); return kIOReturnNotReady; }

    size_t len = mbuf_pkthdr_len(m);
    if (!len) len = mbuf_len(m);
    if (len < 24 || len > 4096) {
        mbuf_freem(m);
        return kIOReturnBadArgument;
    }

    uint8_t *frame = (uint8_t *)IOMalloc(len);
    if (!frame) { mbuf_freem(m); return kIOReturnNoMemory; }
    errno_t err = mbuf_copydata(m, 0, len, frame);
    mbuf_freem(m);
    if (err) { IOFree(frame, len); return kIOReturnError; }

    bool ok = backend->txRawManagementFrame(frame, (uint32_t)len);
    IOFree(frame, len);
    return ok ? kIOReturnSuccess : kIOReturnError;
}

int AirPortRTW::outputActionFrame(IO80211Interface *interface, mbuf_t m)
{
    if (__atomic_load_n(&_shutdown, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&_pmTransition, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&_dmaStopped, __ATOMIC_ACQUIRE) ||
        (_awdlManager && _awdlManager->powerSuspended())) {
        if (m) mbuf_freem(m);
        return kIOReturnNotReady;
    }
    (void)interface;
    IOLog("AirPortRTW: infrastructure action TX len=%zu\n", m ? mbuf_pkthdr_len(m) : 0);
    return rtw88SendActionFrame(_ieee80211, m);
}

int AirPortRTW::bpfOutputPacket(OSObject *object, UInt dltType, mbuf_t m)
{
    __atomic_fetch_add(&_awdlTxBpfCalls, 1U, __ATOMIC_RELAXED);
    __atomic_store_n(&_awdlTxBpfLastDlt, (uint32_t)dltType, __ATOMIC_RELAXED);
    if (dltType == DLT_EN10MB)
        traceAWDLTxPacket(m, 2);
    if (__atomic_load_n(&_shutdown, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&_pmTransition, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&_dmaStopped, __ATOMIC_ACQUIRE) ||
        (_awdlManager && _awdlManager->powerSuspended())) {
        if (m) mbuf_freem(m);
        return kIOReturnNotReady;
    }
    IO80211VirtualInterface *vif = OSDynamicCast(IO80211VirtualInterface, object);
    IOLog("AirPortRTW: VIF bpfOutput dlt=%u role=%d len=%zu\n",
          dltType, vif ? vif->getInterfaceRole() : 0, m ? mbuf_pkthdr_len(m) : 0);

    const bool awdl = vif && vif->getInterfaceRole() == APPLE80211_VIF_AWDL;
    if (dltType == DLT_RAW || dltType == DLT_IEEE802_11) {
        if (awdl && _awdlManager)
            return _awdlManager->enqueueActionFrame(m) ? kIOReturnSuccess : kIOReturnNoResources;
        return rtw88SendActionFrame(_ieee80211, m);
    }

    if (dltType == DLT_IEEE802_11_RADIO && m) {
        /* Minimal radiotap decapsulation: bytes 2..3 are the little-endian
         * radiotap header length.  AWDL action frames are then ordinary
         * native 802.11 management frames for the rtw88 MGMT queue. */
        uint8_t hdr[4] = {};
        if (mbuf_pkthdr_len(m) < sizeof(hdr) ||
            mbuf_copydata(m, 0, sizeof(hdr), hdr) != 0) {
            mbuf_freem(m);
            return kIOReturnBadArgument;
        }
        uint16_t rtlen = (uint16_t)hdr[2] | ((uint16_t)hdr[3] << 8);
        size_t total = mbuf_pkthdr_len(m);
        if (rtlen < 4 || rtlen >= total) {
            mbuf_freem(m);
            return kIOReturnBadArgument;
        }
        mbuf_adj(m, (int)rtlen);
        if (awdl && _awdlManager)
            return _awdlManager->enqueueActionFrame(m) ? kIOReturnSuccess : kIOReturnNoResources;
        return rtw88SendActionFrame(_ieee80211, m);
    }

    if (m) mbuf_freem(m);
    return kIOReturnUnsupported;
}

void AirPortRTW::requestPacketTx(void *object, UInt options)
{
    drainAWDLTxPackets(object, options, false);
}

void AirPortRTW::drainAWDLTxPackets(void *object, UInt options, bool timerPoll)
{
    __atomic_fetch_add(timerPoll ? &_awdlTxTimerPolls : &_awdlTxSystemCallbacks,
                       1U, __ATOMIC_RELAXED);
    __atomic_store_n(&_awdlTxLastOptions, (uint32_t)options, __ATOMIC_RELAXED);
    if (__atomic_load_n(&_shutdown, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&_pmTransition, __ATOMIC_ACQUIRE) ||
        (_awdlManager && _awdlManager->powerSuspended()) ||
        !_ieee80211 || !_ieee80211->isPowered()) {
        __atomic_fetch_add(&_awdlTxRejectedPower, 1U, __ATOMIC_RELAXED);
        return;
    }
    if (__atomic_load_n(&_dmaStopped,__ATOMIC_ACQUIRE)) {
        __atomic_fetch_add(&_awdlTxRejectedDma, 1U, __ATOMIC_RELAXED);
        return;
    }
    RTW88TxDrainGuard drainGuard(&_awdlTxDrainActive);
    if (!drainGuard.acquired()) {
        __atomic_fetch_add(&_awdlTxReentrantSkipped, 1U, __ATOMIC_RELAXED);
        return;
    }
    IO80211VirtualInterface *vif = OSDynamicCast(IO80211VirtualInterface, (OSObject *)object);
    if (!vif || !_ieee80211 || vif->getInterfaceRole() != APPLE80211_VIF_AWDL) {
        __atomic_fetch_add(&_awdlTxRejectedObject, 1U, __ATOMIC_RELAXED);
        return;
    }

    // Do not query isOutputFlowControlled through this private SDK vtable.
    // Beta 16's slot dispatched _outputStartGated on Darwin 25 and recursively
    // called requestPacketTx, exhausting the kernel stack (drain + 0x1c1).
    ++_awdlTxRequestCallbacks;
    setProperty("AWDL_TX_REQUEST_CALLBACKS", (uint64_t)_awdlTxRequestCallbacks, 32);

    if (!_awdlManager) return;
    if (!_awdlManager->scheduleReady()) {
        ++_awdlTxScheduleNotReady;
        setProperty("AWDL_TX_SCHEDULE_NOT_READY", (uint64_t)_awdlTxScheduleNotReady, 32);
        /* Beta 8 returned here and could leave Bonjour/IPv6 in IO80211's
         * private queues. Beta 9 takes ownership now and lets the AWDL
         * manager wait for a safe RF window. */
    }

    static const IOMbufServiceClass classes[] = {
        kIOMbufServiceClassCTL, kIOMbufServiceClassVO, kIOMbufServiceClassVI,
        kIOMbufServiceClassRV, kIOMbufServiceClassAV, kIOMbufServiceClassOAM,
        kIOMbufServiceClassRD, kIOMbufServiceClassBE, kIOMbufServiceClassBK,
        kIOMbufServiceClassBKSYS
    };
    static const char *classProps[] = {
        "AWDL_TX_CLASS_CTL", "AWDL_TX_CLASS_VO", "AWDL_TX_CLASS_VI",
        "AWDL_TX_CLASS_RV", "AWDL_TX_CLASS_AV", "AWDL_TX_CLASS_OAM",
        "AWDL_TX_CLASS_RD", "AWDL_TX_CLASS_BE", "AWDL_TX_CLASS_BK",
        "AWDL_TX_CLASS_BKSYS"
    };

    UInt32 accepted = 0;
    for (unsigned cidx = 0; cidx < sizeof(classes) / sizeof(classes[0]); cidx++) {
        mbuf_t head = nullptr, tail = nullptr;
        UInt count = 0;
        unsigned long long bytes = 0;

        ++_awdlTxDequeueCalls;
        const bool dequeueResult = vif->dequeueOutputPacketsWithServiceClass(32, classes[cidx],
                                                        &head, &tail,
                                                        &count, &bytes);
        /* The SDK declares a bool, not an IOReturn. Record true/false without
         * assigning error semantics or changing the existing ownership path. */
        __atomic_fetch_add(dequeueResult ? &_awdlTxDequeueTrue : &_awdlTxDequeueFalse,
                           1U, __ATOMIC_RELAXED);
        __atomic_fetch_add(dequeueResult ? &_awdlTxClassTrue[cidx] : &_awdlTxClassFalse[cidx],
                           1U, __ATOMIC_RELAXED);
        if (dequeueResult && !head)
            __atomic_fetch_add(&_awdlTxDequeueTrueEmpty, 1U, __ATOMIC_RELAXED);
        if (!dequeueResult && head)
            __atomic_fetch_add(&_awdlTxDequeueFalseWithHead, 1U, __ATOMIC_RELAXED);
        if (!head) {
            ++_awdlTxEmptyDequeues;
        } else {
            _awdlTxDequeuePackets += count;
            _awdlTxDequeueBytes += bytes;
            _awdlTxClassPackets[cidx] += count;
            setProperty(classProps[cidx], (uint64_t)_awdlTxClassPackets[cidx], 32);
        }

        UInt actual = 0;
        mbuf_t m = head;
        while (m) {
            ++actual;
            __atomic_fetch_add(&_awdlTxActualDequeued, 1U, __ATOMIC_RELAXED);
            mbuf_t next = mbuf_nextpkt(m);
            mbuf_setnextpkt(m, nullptr);

            traceAWDLTxPacket(m, 0);

            const RTW88MdnsInfo mdns = rtw88InspectAWDLMdnsPacket(m);
            if (mdns.ipv6) {
                ++_awdlIPv6Tx;
                setProperty("AWDL_IPV6_TX", (uint64_t)_awdlIPv6Tx, 32);
            }
            if (mdns.mdns) {
                ++_awdlMdnsTx;
                if (mdns.response) ++_awdlMdnsTxResponses;
                else ++_awdlMdnsTxQueries;
                if (mdns.airDrop) {
                    ++_awdlAirDropMdnsTx;
                    if (mdns.response) ++_awdlAirDropMdnsTxResponses;
                    else ++_awdlAirDropMdnsTxQueries;
                }
                setProperty("AWDL_MDNS_TX", (uint64_t)_awdlMdnsTx, 32);
                setProperty("AWDL_MDNS_TX_QUERIES", (uint64_t)_awdlMdnsTxQueries, 32);
                setProperty("AWDL_MDNS_TX_RESPONSES", (uint64_t)_awdlMdnsTxResponses, 32);
                setProperty("AWDL_AIRDROP_MDNS_TX", (uint64_t)_awdlAirDropMdnsTx, 32);
                setProperty("AWDL_AIRDROP_MDNS_TX_QUERIES", (uint64_t)_awdlAirDropMdnsTxQueries, 32);
                setProperty("AWDL_AIRDROP_MDNS_TX_RESPONSES", (uint64_t)_awdlAirDropMdnsTxResponses, 32);
                if (mdns.serviceIdValid)
                    _awdlManager->noteLocalAirDropServiceId(mdns.serviceId, 12);
            }

            if (_awdlManager->enqueueData(m)) {
                ++accepted;
                ++_awdlTxEnqueueSuccess;
            } else {
                ++_awdlTxEnqueueFailure;
            }
            m = next;
        }
        if (actual != count)
            __atomic_fetch_add(&_awdlTxDequeueCountMismatch, 1U, __ATOMIC_RELAXED);
    }

    setProperty("AWDL_TX_DEQUEUE_CALLS", (uint64_t)_awdlTxDequeueCalls, 32);
    setProperty("AWDL_TX_DEQUEUE_PACKETS", (uint64_t)_awdlTxDequeuePackets, 32);
    setProperty("AWDL_TX_DEQUEUE_BYTES", _awdlTxDequeueBytes, 64);
    setProperty("AWDL_TX_EMPTY_DEQUEUES", (uint64_t)_awdlTxEmptyDequeues, 32);
    setProperty("AWDL_TX_CONTROLLER_ENQUEUE_SUCCESS", (uint64_t)_awdlTxEnqueueSuccess, 32);
    setProperty("AWDL_TX_CONTROLLER_ENQUEUE_FAILURE", (uint64_t)_awdlTxEnqueueFailure, 32);
    setProperty("AWDL_LAST_DEQUEUE_COUNT", (uint64_t)accepted, 32);
    (void)options;
}


void AirPortRTW::awdlTimerFired(OSObject *owner, IOTimerEventSource *)
{
    auto *self = OSDynamicCast(AirPortRTW, owner);
    if (!self || !self->_awdlManager ||
        __atomic_load_n(&self->_pmTransition, __ATOMIC_ACQUIRE) ||
        self->_awdlManager->powerSuspended() ||
        __atomic_load_n(&self->_shutdown,__ATOMIC_ACQUIRE) ||
        __atomic_load_n(&self->_dmaStopped,__ATOMIC_ACQUIRE)) return;
    if (!self->_awdlManager->awdlInterface()) {
        const bool ready = self->ensureAWDLVirtualInterface();
        self->setProperty("AWDL_BOOTSTRAP_READY", ready ? kOSBooleanTrue : kOSBooleanFalse);
        if (!ready) return;
    }
    if (self->_awdlManager->tick()) {
        auto *vif = self->_awdlManager->awdlInterface();
        if (vif) self->drainAWDLTxPackets(vif, 0, true);
    }

    /* Retire peers from IO80211 when their AWDL advertisements have actually
     * gone stale. Earlier builds only posted presence, so a transient peer
     * could remain visible to Finder/sharingd after the radio relationship
     * had already disappeared. */
    uint8_t expired[8 * 6] = {};
    const uint32_t expiredCount = self->_awdlManager->expirePublishedPeers(expired, 8);
    auto *p2p = OSDynamicCast(IO80211P2PInterface, self->_awdlManager->awdlInterface());
    if (p2p) {
        for (uint32_t i = 0; i < expiredCount; ++i) {
            ether_addr peer = {};
            memcpy(peer.octet, expired + i * 6, sizeof(peer.octet));
            (void)p2p->postPeerAbsence(&peer);
            ++self->_awdlPeerAbsencePosts;
        }
        if (expiredCount)
            self->setProperty("AWDL_PEER_ABSENCE_POSTS", (uint64_t)self->_awdlPeerAbsencePosts, 32);
    }
    /* If tick() returned the PHY to the AP channel, release any en0 packet
     * that was deliberately stalled while AWDL owned the radio. */
    if (self->_ieee80211 && !self->_ieee80211->staTxBlockedByAWDL())
        self->resumeTxIfStalled();
}
