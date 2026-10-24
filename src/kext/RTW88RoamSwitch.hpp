/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include "RTW88Roaming.hpp"
namespace RTW88RoamSwitch {
constexpr uint64_t FreshMs=30000, AttemptMs=15000, CooldownMs=60000;
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
