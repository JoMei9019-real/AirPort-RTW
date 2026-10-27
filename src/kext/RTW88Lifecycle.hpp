/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include <stdint.h>
#include <string.h>
namespace RTW88Lifecycle {
enum WakePoint : unsigned {RadioReady,ScanStart,ScanDone,Connect,Auth,Assoc,Keys,Data,WakePoints};
struct Wake {
    uint32_t generation=0;
    uint64_t begin=0, points[WakePoints]={};
    uint8_t firstAP[6]={};unsigned firstChannel=0;
    bool active=false;
    void start(uint64_t now) {
        ++generation;begin=now;memset(points,0,sizeof(points));
        memset(firstAP,0,6);firstChannel=0;active=true;
    }
    bool mark(unsigned point,uint64_t now,const uint8_t*ap,unsigned channel) {
        if(!active||point>=WakePoints||points[point]||now<begin)return false;
        points[point]=now;
        if(point==Keys){memcpy(firstAP,ap,6);firstChannel=channel;}
        if(point==Data)active=false;
        return true;
    }
};
struct BtmOutcome {
    uint64_t requestMs=0,decisionMs=0,ackMs=0,switchMs=0,cooldownMs=0;
    uint32_t result=0,reason=0;
    uint8_t source[6]={},target[6]={},token=0,mode=0;
    uint8_t status=255;bool responseSubmitted=false;
    const char *stage="none";
};
enum TxEvent : unsigned {
    StallPower,StallScan,StallAWDL,StallRing,DropOffline,DropKeys,DropEncap,
    Submitted,StartCalls,GateAWDLChecks,GateScanChecks,GateRingChecks,GateDepthChecks,QueueResumes,TxEvents
};
struct Queue {
    uint32_t events[TxEvents]={};
    uint64_t sampleMs=0,dropTotal=0,stallTotal=0,dropDelta=0,stallDelta=0;
    unsigned queued=0,state=0;
    bool primed=false;
    void sample(uint64_t now,uint64_t drops,uint64_t stalls,unsigned depth,unsigned currentState) {
        dropDelta=primed&&drops>=dropTotal?drops-dropTotal:0;
        stallDelta=primed&&stalls>=stallTotal?stalls-stallTotal:0;
        dropTotal=drops;stallTotal=stalls;queued=depth;state=currentState;sampleMs=now;primed=true;
    }
};
}
