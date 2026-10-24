/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include "RTW88Roaming.hpp"
namespace RTW88RoamSwitch {
constexpr uint64_t FreshMs=30000, AttemptMs=15000, CooldownMs=60000;
constexpr uint64_t RefreshIntervalMs=5000, ScanIntervalMs=5000;
enum Reason : unsigned {
    Ready, Disabled, PowerBlocked, NotConnected, SecurityMode, KeysMissing,
    AuthBusy, InvalidTarget, CurrentTarget, SwitchBusy, Cooldown,
    NeighborMissing, NeighborStale, TargetNotListed, ScanMissing, SSIDMismatch,
    ChannelMismatch, SignalWeak, ScanStale, TargetSecurity, ChannelMissing,
    ChannelDisabled, ChannelNoIR, ChannelDFS, CurrentSecurity, RefreshPending,
    RefreshLimited, APNoNeighbor, RefreshTxFailed, ScanBusy, ScanLimited,
    ScanStartFailed
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
        "scan-busy", "scan-rate-limited", "scan-start-failed"
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
