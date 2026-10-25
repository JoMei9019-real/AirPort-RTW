/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include "RTW88Roaming.hpp"
namespace RTW88RoamSwitch {
constexpr uint64_t FreshMs=30000, AttemptMs=15000, CooldownMs=60000;
constexpr uint64_t RefreshIntervalMs=5000, ScanIntervalMs=5000;
constexpr uint16_t DiscoveryChannel=0xffff;
constexpr unsigned MaxDiscoveryChannels=64;
constexpr int Prefer5GHzRSSI=-70, Keep5GHzRSSI=-77, MinimumRSSI=-80, SameBandGain=6;
inline bool band5(unsigned frequency) { return frequency>=5000 && frequency<=5900; }
// DS/HT operation describes the AP's primary channel. RX frequency may be
// the adjacent scan channel on which a 2.4 GHz management frame was heard.
inline unsigned channelFrequency(unsigned channel) {
    if(channel==14)return 2484;
    if(channel>=1 && channel<=13)return 2407+5*channel;
    if(channel>=32 && channel<=177)return 5000+5*channel;
    return 0;
}
// Compare bands by suitability first, RSSI only within a class. A weak 5 GHz
// link must not outrank usable 2.4 GHz merely because of the frequency band.
inline int rank(unsigned frequency,int rssi,bool current5=false) {
    if(rssi<MinimumRSSI || rssi>=0)return -10000;
    if(band5(frequency) && rssi>=(current5?Keep5GHzRSSI:Prefer5GHzRSSI))return 1000+rssi;
    if(frequency>=2400 && frequency<=2500)return 500+rssi;
    return band5(frequency)?rssi:-10000;
}
inline bool beaconProof(uint16_t fc,uint16_t sequence,uint32_t caps,unsigned channel,
                        unsigned frequency,bool complete,const uint8_t *sender,const uint8_t *bssid) {
    const unsigned expected=channel==14?2484:channel<=13?2407+5*channel:5000+5*channel;
    return (fc&0xc7ff)==0x0080 && !(sequence&15) && (caps&3)==1 && channel &&
        complete && frequency==expected && sender && bssid &&
        !memcmp(sender,bssid,6) && RTW88Roaming::unicast(bssid);
}
enum Reason : unsigned {
    Ready, Disabled, PowerBlocked, NotConnected, SecurityMode, KeysMissing,
    AuthBusy, InvalidTarget, CurrentTarget, SwitchBusy, Cooldown,
    NeighborMissing, NeighborStale, TargetNotListed, ScanMissing, SSIDMismatch,
    ChannelMismatch, SignalWeak, ScanStale, TargetSecurity, ChannelMissing,
    ChannelDisabled, ChannelNoIR, ChannelDFS, CurrentSecurity, RefreshPending,
    RefreshLimited, APNoNeighbor, RefreshTxFailed, ScanBusy, ScanLimited,
    ScanStartFailed, BeaconMissing, NoCandidate, KeepCurrent,
    LinkInvisible, AuthCancelled, AWDLOffChannel, HomeChannelMismatch
};
inline const char *reasonName(unsigned reason) {
    static const char *const names[] = {
        "ready", "disabled", "power-transition-or-off", "not-connected",
        "unsupported-security-mode", "keys-not-ready", "authentication-worker-busy",
        "invalid-target", "target-is-current-ap", "switch-in-progress", "switch-cooldown",
        "neighbor-report-missing", "neighbor-report-stale", "target-not-in-neighbor-report",
        "target-not-in-scan-cache", "ssid-mismatch", "neighbor-scan-channel-mismatch",
        "signal-too-weak-or-invalid", "target-scan-stale", "target-security-incompatible",
        "channel-not-in-regulatory-table", "channel-disabled", "channel-no-ir",
        "dfs-channel-excluded", "current-security-incompatible", "neighbor-request-pending",
        "neighbor-request-rate-limited", "ap-no-neighbor-report", "neighbor-request-tx-failed",
        "scan-busy", "scan-rate-limited", "scan-start-failed",
        "fresh-ap-beacon-required", "no-eligible-candidate", "current-ap-preferred",
        "link-not-visible", "authentication-cancelled", "awdl-off-channel", "home-channel-not-restored"
    };
    return reason < sizeof(names)/sizeof(names[0]) ? names[reason] : "unknown";
}
inline uint64_t age(uint64_t now, uint64_t observed) {
    return observed && now>=observed ? now-observed : ~uint64_t(0);
}
struct Transaction {
    unsigned phase=0;
    uint64_t started=0;
    uint8_t oldAP[6]={}, target[6]={}, pmk[32]={};
    char ssid[33]={};
    void clear() {
        volatile uint8_t *p=pmk;
        for(unsigned i=0;i<sizeof(pmk);++i)p[i]=0;
        memset(oldAP,0,sizeof(oldAP));memset(target,0,sizeof(target));
        memset(ssid,0,sizeof(ssid));phase=0;started=0;
    }
};
inline bool fresh(uint64_t now,uint64_t observed) {
    return observed && now>=observed && now-observed<FreshMs;
}
inline bool security(const uint8_t *ies,size_t length) {
    if(!ies || length>512)return false;
    bool selected=false;
    while(length){
        if(length<2 || ies[1]>length-2)return false;
        if(ies[0]==48){
            RTW88Enterprise::Rsn r;
            if(selected || !RTW88Enterprise::parse(ies+2,ies[1],r) ||
               !r.psk || !r.ccmp || r.group!=RTW88Enterprise::Ccmp ||
               (r.caps&0x40))return false;
            selected=true;
        }
        size_t n=size_t(ies[1])+2;ies+=n;length-=n;
    }
    return selected;
}
}
