/* Modified by X1REN41L on 2026-10-02 for AirPortRTW 1.0.0; see the repository NOTICE.md. */
/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * RTW88AWDLManager.hpp — shared AWDL/P2P state for AirPortRTW 1.0.1.
 *
 * This class intentionally contains no private Apple ABI layouts. It owns the
 * verified AWDL state that is shared between IO80211 virtual-interface IOCTLs
 * and the Realtek management-frame transport.
 */
#pragma once

#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOService.h>
#include <sys/kpi_mbuf.h>
#include "RTW88AWDLProtocol.hpp"


class RTW88IEEE80211;
class IO80211VirtualInterface;

class RTW88AWDLManager {
public:
    /* IO80211 owns AWDL policy/control.  These bits record which parts of the
     * Ventura control-plane macOS has actually supplied; OpenAWDL-style
     * fallback is only a bootstrap when Apple has not provided a template. */
    enum AppleControl : uint32_t {
        kAppleCtlVIF             = 1u << 0,
        kAppleCtlSyncEnabled     = 1u << 1,
        kAppleCtlTemplate        = 1u << 2,
        kAppleCtlMasterChannel   = 1u << 3,
        kAppleCtlChannelSequence = 1u << 4,
        kAppleCtlSyncParams      = 1u << 5,
        kAppleCtlPresence        = 1u << 6,
        kAppleCtlSyncState       = 1u << 7,
        kAppleCtlElection        = 1u << 8,
    };

    RTW88AWDLManager() = default;
    ~RTW88AWDLManager();

    bool init(RTW88IEEE80211 *backend, IOWorkLoop *workLoop,
              IOService *owner, IOTimerEventSource::Action action);
    void reset();
    void scheduleDiscovery();
    void suspendForPowerTransition();
    bool powerSuspended() const { return __atomic_load_n(&_powerSuspended, __ATOMIC_ACQUIRE); }
    void resumeAfterPowerTransition();

    void setVirtualInterface(UInt role, IO80211VirtualInterface *interface);
    void clearVirtualInterface(IO80211VirtualInterface *interface);
    IO80211VirtualInterface *awdlInterface() const { return _awdlInterface; }
    IO80211VirtualInterface *p2pInterface() const { return _p2pInterface; }

    bool syncEnabled() const { return _syncEnabled; }
    void setSyncEnabled(bool enabled);
    void noteAppleControl(uint32_t bit);
    uint32_t appleControlMask() const { return _appleControlMask; }
    void setLocalAddress(const uint8_t *mac);
    bool observeAction(const uint8_t *frame, uint32_t length, bool *presenceDue = nullptr);
    uint32_t expirePublishedPeers(uint8_t *outMacs, uint32_t capacity);
    bool enqueueActionFrame(mbuf_t m); // consumes the mbuf on every path
    bool enqueueData(mbuf_t m); // consumes the mbuf on every path
    bool tick(); // true when the controller should pull more packets
    bool scheduleReady() const { return !powerSuspended() && _syncEnabled && _awdlInterface && _airTemplate; }
    void publishStats();
    void noteDataRX(uint32_t result);
    void noteLocalAirDropServiceId(const uint8_t *serviceId, uint8_t length);

    uint32_t electionMetric() const { return _electionMetric; }
    void setElectionMetric(uint32_t metric) { _electionMetric = metric; }

    void setBSSID(const uint8_t *bssid);
    void getBSSID(uint8_t *bssid) const;
    uint32_t electionId() const { return _electionId; }
    void setElectionId(uint32_t v) { _electionId = v; }
    uint32_t masterChannel() const { return _masterChannel; }
    uint32_t reportedChannel() const;
    uint32_t reportedMasterChannel() const;
    const char *reportedChannelSource() const;
    void setMasterChannel(uint32_t v);
    uint32_t secondaryMasterChannel() const { return _secondaryMasterChannel; }
    void setSecondaryMasterChannel(uint32_t v) { _secondaryMasterChannel = v; }
    uint8_t minRate() const { return _minRate; }
    void setMinRate(uint8_t v) { _minRate = v; }
    uint32_t presenceMode() const { return _presenceMode; }
    void setPresenceMode(uint32_t v) { _presenceMode = v; }
    uint32_t syncState() const { return _syncState; }
    void setSyncState(uint32_t v) { _syncState = v; }
    uint8_t deviceCapabilities() const { return _deviceCapabilities; }
    void setDeviceCapabilities(uint8_t v) { _deviceCapabilities = v; }
    uint64_t actionFrameTxMode() const { return _actionFrameTxMode; }
    void setActionFrameTxMode(uint64_t v) { _actionFrameTxMode = v; }

    IOReturn setSyncChannelSequence(const void *data, uint32_t length);
    IOReturn copySyncChannelSequence(void *data, uint32_t length) const {
        if (!data || !_syncChannelSequenceLength || length < _syncChannelSequenceLength)
            return kIOReturnNotReady;
        memcpy(data, _syncChannelSequence, _syncChannelSequenceLength);
        return kIOReturnSuccess;
    }

    void setSyncParams(uint32_t awLen, uint32_t awPeriod, uint32_t extLen, uint32_t syncPeriod);
    bool syncParamsValid() const { return _syncParamsValid; }
    uint32_t availabilityWindowLength() const { return _availabilityWindowLength; }
    uint32_t availabilityWindowPeriod() const { return _availabilityWindowPeriod; }
    uint32_t extensionLength() const { return _extensionLength; }
    uint32_t synchronizationFramePeriod() const { return _synchronizationFramePeriod; }

    IOReturn setSyncFrameTemplate(const void *payload, uint32_t length, bool fromIO80211 = true);
    IOReturn copySyncFrameTemplate(void *payload, uint32_t *length) const;

    void setP2PEnabled(bool enabled) { _p2pEnabled = enabled; }
    bool p2pEnabled() const { return _p2pEnabled; }

    void notePeerTrafficRegistration(bool active, const char *name, uint32_t nameLength);
    uint32_t peerRegistrationCount() const { return _peerRegistrations; }
    bool receiverIntent() const { return _receiverIntent; }
    bool airDropRegistrationActive() const { return _airDropRegistrations != 0; }

    bool hasVirtualTransport() const {
        return _awdlInterface != nullptr || _p2pInterface != nullptr;
    }

private:
    static bool isConcreteChannel(uint32_t ch) { return ch > 0 && ch <= 196 && ch != 0xff; }
    void bootstrapNative(); // caller holds workloop gate
    void flushActions();
    void drainActions(uint64_t now);
    void refreshReceiverIntent(uint64_t now);
    bool _nativeSchedule = false;
    uint32_t _appleControlMask = 0;
    uint64_t _lastAppleControlUS = 0;
    uint64_t _vifEnabledUS = 0;
    uint64_t _fallbackDeadlineUS = 0;
    uint64_t _masterSeenUS = 0;
    uint32_t _dataRx = 0, _lastDataRxResult = 0;
    void arm(uint32_t milliseconds);
    void flushData();
    void drainData(uint64_t now, const RTW88AWDL::Window &window);
    static uint64_t nowUS();
    IOTimerEventSource *_timer = nullptr;
    bool _timerAttached = false;
    bool _powerSuspended = false;
    uint32_t _powerSuspends = 0, _powerResumes = 0;
    IOService *_owner = nullptr; // timer owner, non-retained
    uint8_t _localAddress[6] = {};
    uint8_t *_airTemplate = nullptr;
    uint8_t *_txBuffer = nullptr;
    uint32_t _airTemplateLength = 0;
    RTW88AWDL::Action _action;
    RTW88AWDL::Clock _clock;
    uint64_t _nextActionUS = 0, _nextPSFUS = 0, _lastStatsUS = 0;
    uint32_t _lastMIFEAW = 0;
    bool _lastMIFEAWValid = false;
    uint16_t _actionSequence = 0;
    uint32_t _actionTx = 0, _psfTx = 0, _mifTx = 0, _actionRx = 0, _dataTx = 0, _dataDropped = 0, _syncUpdates = 0;
    uint32_t _dataEnqueueSuccess = 0, _dataEnqueueFailure = 0, _dataQueueHighWater = 0;
    uint32_t _dataTxAttempts = 0, _dataTxFailures = 0, _dataWindowDeferred = 0;
    uint32_t _dataPeerDeferred = 0, _dataRadioDeferred = 0, _dataExpired = 0;
    uint32_t _dataMulticastQueued = 0, _dataUnicastQueued = 0;
    uint32_t _appleActionQueued = 0, _appleActionTx = 0, _appleActionDropped = 0, _appleActionRestamped = 0;
    uint32_t _bpfTemplateAdoptions = 0;
    uint32_t _blockedWindows = 0, _windowSkips = 0;
    uint32_t _socialSweeps = 0;
    uint64_t _nextSocialSweepUS = 0;
    uint8_t _discoverySocialIndex = 0;
    uint8_t _discoveryChannel = 6;
    uint8_t _observedMasterChannel = 0;
    uint8_t _nextAWChannel = 0;
    uint32_t _masterChannelRaw = 0;
    uint32_t _actionCandidates = 0, _actionParseRejected = 0, _actionClockRejected = 0;
    uint32_t _electionMismatchTolerated = 0, _sameChannelWindows = 0, _offChannelWindows = 0;
    uint32_t _trailingPaddingAccepted = 0, _peerRefreshes = 0, _peerExpires = 0, _peerServiceRefreshes = 0;
    uint32_t _retuneAttempts = 0, _retuneSuccess = 0, _retuneNotReady = 0, _sameChannelFastPath = 0;
    uint32_t _retuneUnsupported = 0, _retuneBusy = 0, _retuneOther = 0, _noChannelWindows = 0;
    uint32_t _peerScheduleWindows = 0, _peerScheduleSameChannel = 0, _peerScheduleOffChannel = 0;
    uint32_t _nativeBootstrapWindows = 0, _busyState = 0;
    uint32_t _peerNextAWFallbackWindows = 0, _peerSequenceHomeMatches = 0;
    uint8_t _peerSequenceZeroSlots = 0, _peerSequenceNonzeroSlots = 0;
    uint8_t _peerSequenceEncoding = 0, _peerSequenceStride = 0, _peerScheduleNextAW = 0;
    uint16_t _windowTargetChannel = 0, _radioChannelBefore = 0, _radioChannelAfter = 0;
    uint32_t _mifRx = 0, _versionRx = 0, _mifPeersObserved = 0, _versionPeersObserved = 0;
    uint32_t _serviceResponseRx = 0, _serviceParamsRx = 0, _dataPathStateRx = 0, _arpaRx = 0, _bloomRx = 0;
    uint32_t _rxTlvMask = 0;
    uint16_t _rxMifLength = 0, _rxServiceResponseLength = 0, _rxServiceParamsLength = 0;
    uint16_t _rxDataPathStateLength = 0, _rxArpaLength = 0, _rxBloomLength = 0;
    uint16_t _rxServiceValueLength = 0, _rxServiceFragmentOffset = 0;
    uint16_t _rxDataPathFlags = 0, _rxDataPathSocialChannels = 0, _rxDataPathExtFlags = 0;
    uint16_t _rxDataPathInfraChannel = 0, _rxDataPathUmi = 0, _rxDataPathUnicastOptionsLength = 0;
    uint8_t _rxDataPathInfraBSSID[6] = {}, _rxDataPathInfraAddress[6] = {}, _rxDataPathAWDLAddress[6] = {};
    bool _rxDataPathLayoutValid = false;
    uint16_t _rxServiceUpdateIndex = 0; uint32_t _rxServiceBitmask = 0;
    uint8_t _rxServiceKeyLength = 0, _rxServiceDnsType = 0, _rxServiceResponseCount = 0;
    uint8_t _rxServicePtrCount = 0, _rxServiceTxtCount = 0, _rxServiceSrvCount = 0, _rxServiceOtherCount = 0;
    uint8_t _rxArpaFlags = 0, _rxArpaNameLength = 0;
    uint8_t _localAirDropServiceId[12] = {};
    uint8_t _localAirDropServiceIdLength = 0;
    uint32_t _localAirDropServiceCaptures = 0, _nativeServiceResponseTx = 0;
    uint64_t _lastRejectReportUS = 0, _lastActionRxUS = 0, _lastValidPeerUS = 0;
    IOReturn _lastChannelResult = kIOReturnNotReady;
    struct Peer {
        uint8_t mac[6] = {};
        uint64_t seenUS = 0;
        RTW88AWDL::Sequence sequence;
        RTW88AWDL::Clock clock;
        uint16_t commonLength = 0;
        uint8_t nextAwChannel = 0;
        bool sawMIF = false, versionValid = false, valid = false, announced = false;
        bool sawServiceParams = false, sawDataPathState = false, sawArpa = false;
        bool sawServiceResponse = false, serviceReadyNotified = false;
        uint64_t lastPresenceUS = 0;
        uint8_t version = 0, deviceClass = 0;
    } _peers[32];
    struct Pending { mbuf_t packet = nullptr; uint64_t queuedUS = 0; } _pending[128];
    uint16_t _queueHead = 0, _queueCount = 0;
    struct PendingAction { mbuf_t packet = nullptr; uint64_t queuedUS = 0; } _pendingActions[32];
    uint8_t _actionQueueHead = 0, _actionQueueCount = 0;
    RTW88IEEE80211 *_backend = nullptr;       // non-retained, controller owns
    IOWorkLoop *_workLoop = nullptr;          // non-retained, controller owns
    IO80211VirtualInterface *_awdlInterface = nullptr;
    IO80211VirtualInterface *_p2pInterface = nullptr;

    uint8_t *_syncTemplate = nullptr;
    uint32_t _syncTemplateLength = 0;
    uint32_t _electionMetric = 0;
    uint32_t _electionId = 0;
    uint32_t _masterChannel = 0;
    uint32_t _secondaryMasterChannel = 0;
    uint32_t _peerRegistrations = 0;
    uint32_t _airDropRegistrations = 0;
    uint32_t _peerTrafficRegistrationEvents = 0;
    uint32_t _airDropRegistrationEvents = 0;
    uint32_t _receiverStateEntries = 0;
    uint32_t _peerTrafficLastNameLength = 0;
    uint32_t _receiverMdnsActivations = 0;
    uint32_t _receiverMdnsExpirations = 0;
    uint64_t _receiverLastMdnsUS = 0;
    uint8_t _receiverStateSource = 0; // 0=inactive, 1=peer-traffic, 2=local-mDNS
    bool _receiverIntent = false;
    uint32_t _presenceMode = 0;
    uint32_t _syncState = 0;
    uint64_t _actionFrameTxMode = 0;
    uint8_t _bssid[6] = {};
    uint8_t _minRate = 0;
    uint8_t _deviceCapabilities = 0;
    uint8_t _syncChannelSequence[512] = {};
    uint32_t _syncChannelSequenceLength = 0;
    uint32_t _availabilityWindowLength = 0;
    uint32_t _availabilityWindowPeriod = 0;
    uint32_t _extensionLength = 0;
    uint32_t _synchronizationFramePeriod = 0;
    bool _syncParamsValid = false;
    bool _syncEnabled = true;
    bool _p2pEnabled = false;
};
