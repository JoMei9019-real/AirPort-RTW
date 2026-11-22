// SPDX-License-Identifier: GPL-2.0-only
// Legacy4C peer layout and method signatures from xnpty/RTLAirLink b75abf4.
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/80211/IO80211Controller.h>
#include <IOKit/80211/IO80211VirtualInterface.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/OSByteOrder.h>
#include <mach/kmod.h>
#include <mach-o/loader.h>
#include "AirPortRTWAirBridge.hpp"

using namespace AirPortRTWAirBridge;
extern "C" kmod_info_t kmod_info;
extern "C" IOService *vifController(IO80211VirtualInterface *)
    __asm__("__ZN23IO80211VirtualInterface13getControllerEv");
extern "C" bool processAction(OSObject *, __mbuf *, unsigned, void *, size_t)
    __asm__("__ZN22IO80211AWDLPeerManager23actionFrameProcessInputEP6__mbufjPvm");
extern "C" void lockPeer(OSObject *) __asm__("__ZN18IO80211PeerManager12lockDataPathEv");
extern "C" void unlockPeer(OSObject *) __asm__("__ZN18IO80211PeerManager14unlockDataPathEv");
extern "C" OSObject *findPeer(OSObject *, uint8_t *) __asm__("__ZN22IO80211AWDLPeerManager12findAWDLPeerEPh");
extern "C" OSObject *findBasePeer(OSObject *, uint8_t *) __asm__("__ZN18IO80211PeerManager8findPeerEPh");
extern "C" unsigned matchesMAC(OSObject *, OSObject *, uint8_t *) __asm__("__ZN18IO80211PeerManager15macAddressEqualEP11IO80211PeerPh");
extern "C" OSObject *addPeer(OSObject *, const void *, __mbuf *) __asm__("__ZN22IO80211AWDLPeerManager11addAWDLPeerEPK22apple80211_act_frm_hdrP6__mbuf");

namespace {
bool supportedFamily()
{
    const uint8_t uuid[16] = {0x4c,0x07,0x53,0x8b,0x62,0xeb,0x3d,0x6d,
                              0xae,0xf9,0x93,0xbc,0xdc,0xf4,0x5f,0xab};
    for (auto *ref = kmod_info.reference_list; ref; ref = ref->next) {
        const auto *mod = ref->info;
        if (!mod || strcmp(mod->name, "com.apple.iokit.IO80211FamilyLegacy")) continue;
        const auto *hdr = reinterpret_cast<const mach_header_64 *>(mod->address);
        if (!hdr || mod->size < sizeof(*hdr) || hdr->magic != MH_MAGIC_64 ||
            hdr->sizeofcmds > mod->size - sizeof(*hdr)) return false;
        auto *bytes = reinterpret_cast<const uint8_t *>(hdr + 1);
        size_t left = hdr->sizeofcmds;
        for (unsigned i = 0; i < hdr->ncmds && left >= sizeof(load_command); ++i) {
            const auto *cmd = reinterpret_cast<const load_command *>(bytes);
            if (cmd->cmdsize < sizeof(*cmd) || cmd->cmdsize > left) return false;
            if (cmd->cmd == LC_UUID)
                return cmd->cmdsize == sizeof(uuid_command) &&
                       !memcmp(reinterpret_cast<const uuid_command *>(bytes)->uuid, uuid, sizeof(uuid));
            left -= cmd->cmdsize;
            bytes += cmd->cmdsize;
        }
    }
    return false;
}

template <typename T> T readField(const OSObject *object, size_t offset)
{
    T value;
    memcpy(&value, reinterpret_cast<const uint8_t *>(object) + offset, sizeof(value));
    return value;
}

uint32_t processedFrames(const OSObject *manager)
{
    uint32_t count = 0;
    for (unsigned i = 0; i < 4; ++i)
        count += readField<uint32_t>(manager, 0x8700 + i * sizeof(uint32_t));
    return count;
}
}

class RTWAirBridge : public IOService {
    OSDeclareDefaultStructors(RTWAirBridge)
    bool familyReady = false;
    bool allowPeerAdd = false;
    IOReturn configure(bool enabled, bool admit);
    uint64_t nextAdmissionUS = 0;
public:
    bool start(IOService *provider) override;
    IOReturn callPlatformFunction(const OSSymbol *, bool, void *, void *, void *, void *) override;
};
OSDefineMetaClassAndStructors(RTWAirBridge, IOService)

bool RTWAirBridge::start(IOService *provider)
{
    if (!IOService::start(provider)) return false;
    const bool enabled = provider->getProperty("AirBridgeNativeRequested") == kOSBooleanTrue;
    configure(enabled, provider->getProperty("AirBridgePeerAddRequested") == kOSBooleanTrue);
    return true;
}

IOReturn RTWAirBridge::configure(bool enabled, bool admit)
{
    familyReady = enabled && supportedFamily();
    allowPeerAdd = familyReady && admit;
    setProperty("AirBridgeMode", !enabled ? "passive" : !familyReady ? "unsupported-family" :
                allowPeerAdd ? "peer-admission" : "observe");
    setProperty("AirBridgeFamilyVerified", familyReady ? kOSBooleanTrue : kOSBooleanFalse);
    return enabled && !familyReady ? kIOReturnUnsupported : kIOReturnSuccess;
}

IOReturn RTWAirBridge::callPlatformFunction(const OSSymbol *name, bool wait,
    void *arg1, void *arg2, void *controller, void *arg4)
{
    if (name && name->isEqualTo(kSetMode)) {
        IOService *owner = getProvider();
        if (!owner || owner != controller || isInactive() || !owner->getWorkLoop() ||
            !owner->getWorkLoop()->inGate()) return kIOReturnNotReady;
        const auto *mode = OSDynamicCast(OSString, static_cast<OSObject *>(arg1));
        if (!mode) return kIOReturnBadArgument;
        if (mode->isEqualTo("passive")) return configure(false, false);
        if (mode->isEqualTo("observe")) return configure(true, false);
        if (mode->isEqualTo("peer-admission")) return configure(true, true);
        return kIOReturnBadArgument;
    }
    if (!name || !name->isEqualTo(kCategory))
        return IOService::callPlatformFunction(name, wait, arg1, arg2, controller, arg4);
    const auto *req = static_cast<const ActionRequest *>(arg1);
    auto *out = static_cast<ActionResult *>(arg2);
    IOService *owner = getProvider();
    if (!familyReady || isInactive() || !owner || owner != controller ||
        !req || !out || req->abiVersion != kABIVersion || req->size != sizeof(*req) ||
        !req->vif || !req->packet || !req->metadata || !owner->getWorkLoop() ||
        !owner->getWorkLoop()->inGate()) return kIOReturnNotReady;
    const auto *vifMeta = req->vif->getMetaClass();
    if (strcmp(vifMeta->getClassName(), "IO80211P2PInterface") ||
        vifMeta->getClassSize() < 0xb0 + sizeof(void *) || vifController(req->vif) != owner)
        return kIOReturnUnsupported;
    const auto *abi = OSDynamicCast(OSNumber, req->vif->getProperty(kABIProperty));
    if (!abi || abi->unsigned32BitValue() != kABIVersion) return kIOReturnUnsupported;
    auto *peer = readField<OSObject *>(req->vif, 0xb0);
    if (!peer || strcmp(peer->getMetaClass()->getClassName(), "IO80211AWDLPeerManager") ||
        peer->getMetaClass()->getClassSize() != 0xc528) return kIOReturnNotReady;

    if (!(readField<uint32_t>(peer, 0x8528) & 2) || !readField<uint32_t>(peer, 0xcd4)) {
        return kIOReturnNotReady;
    }
    ActionMetadata meta = *req->metadata;
    const uint32_t stamp = OSSwapHostToBigInt32(static_cast<uint32_t>(req->handoffUS));
    memcpy(meta.reserved3, &stamp, sizeof(stamp));
    const uint32_t before = processedFrames(peer);
    out->appleResult = processAction(peer, req->packet, 12, &meta, sizeof(meta));
    out->flags = kNativeObserved;
    if (processedFrames(peer) != before) {
        out->flags |= kNativeProcessed | kNativePeerLookup;
        lockPeer(peer);
        auto *found = findPeer(peer, meta.source);
        const uint8_t *local = reinterpret_cast<const uint8_t *>(peer) + 0x2801;
        const uint8_t zero[6] = {};
        if (allowPeerAdd && !found && (req->flags & kLocalPeerValid) && meta.rssi < 0 &&
            meta.rssi >= readField<int32_t>(peer, 0x6e84) && !(meta.source[0] & 1) &&
            memcmp(meta.source, zero, 6) && !(local[0] & 1) && memcmp(local, zero, 6) &&
            memcmp(meta.source, local, 6) && req->handoffUS >= nextAdmissionUS &&
            !findBasePeer(peer, meta.source)) {
            nextAdmissionUS = req->handoffUS + 500000;
            addPeer(peer, &meta, req->packet);
            found = findPeer(peer, meta.source);
        }
        if (found && matchesMAC(peer, found, meta.source) == 1) out->flags |= kNativePeerMatched;
        unlockPeer(peer);
    }
    return kIOReturnSuccess;
}
