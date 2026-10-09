#!/usr/bin/env python3
"""Run production event posting and wake sequencing with synchronous OS callbacks."""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'src/kext/AirPortRTW.cpp').read_text()
def method(signature):
    start = source.index(signature)
    pos = source.index('{', start)
    depth, end = 1, pos + 1
    while depth:
        if source[end] == '{': depth += 1
        elif source[end] == '}': depth -= 1
        end += 1
    return source[start:end] + '\n'

query_start = source.index('    case APPLE80211_IOC_LINK_CHANGED_EVENT_DATA: {')
query_end = source.index('\n    case ', query_start + 1)
query = source[query_start:query_end]
assert 'sizeof(*d)' not in query and 'memcpy(data, &d, sizeof(d))' in query
assert '_netif->postMessage(APPLE80211_M_LINK_CHANGED);' not in source
backend = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
assert backend.count('__atomic_store_n(&_disconnectVoluntary, true,') == 2
assert backend.count('__atomic_store_n(&_disconnectVoluntary, false,') == 3

pre = r'''
#include "RTW88LinkEventWire.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
using IOReturn = int; using UInt16 = uint16_t; using resource_size_t = uintptr_t;
constexpr int kIOReturnSuccess=0, kIOReturnBusy=1, kIOReturnNotReady=2, kIOReturnUnsupported=3;
constexpr int kRTW88PowerStateOn=1, kRTW88PowerStateOff=0, kIOPCIConfigCommand=4;
constexpr unsigned kIONetworkLinkValid=1, kIONetworkLinkNoNetworkChange=2;
constexpr int APPLE80211_M_LINK_CHANGED=4, APPLE80211_M_POWER_CHANGED=1;
constexpr int APPLE80211_IOC_LINK_CHANGED_EVENT_DATA=156, APPLE80211_LINK_DOWN_REASON_DEAUTH=2;
constexpr bool kOSBooleanTrue=true, kOSBooleanFalse=false;
template<class... T> void IOLog(const char *, T...) {}
struct PCI { bool memory=false, master=false; UInt16 command=6;
 void setMemoryEnable(bool x){memory=x;} void setBusMasterEnable(bool x){master=x;}
 UInt16 configRead16(int){return command;} };
struct Map { uint64_t getLength(){return 4096;} };
struct Compat { uint64_t resource[3]={},resource_len[3]={}; };
struct RTW88StateResult { int state=0,rssi=-55; };
struct Backend { bool powered=false,visible=false,voluntary=true; int powerResult=0;
 IOReturn cmdPowerOn(){if (!powerResult)powered=true;return powerResult;}
 bool isPowered(){return powered;} bool associatedVisible(){return visible;}
 bool disconnectIsVoluntary(){return voluntary;}
 IOReturn cmdGetState(RTW88StateResult *r){r->rssi=-55;return 0;} };
struct Interrupt { bool enabled=false; void enable(){enabled=true;} void disable(){enabled=false;} };
struct IOBasicOutputQueue { static constexpr int kServiceAsync=1; };
struct IOOutputQueue { unsigned services=0; void service(int){++services;} };
struct AirPortRTW;
struct Interface { AirPortRTW *owner=nullptr; unsigned calls=0; std::vector<unsigned> events;
 RTW88LinkEventData last={}; void postMessage(unsigned,void * =nullptr,unsigned long=0); };
struct AirPortRTW {
 bool _pmTransition=false,_shutdown=false,_dmaStopped=true,_scanInProgress=true;
 bool _scanCacheBootstrapAttempted=true,_assocDoneReported=true,_txStalled=true;
 bool _pmRadioWasPowered=true; unsigned _scanCursor=7,_pmWakeCount=0,_staLinkEventPosts=0;
 unsigned long _pmPowerState=kRTW88PowerStateOff; IOReturn _pmLastWakeResult=-1;
 PCI pci; PCI *_pciDev=&pci; Map map; Map *_mmioMap=&map;
 void *_mmioBase=(void*)1; Compat compat; Compat *_compatPciDev=&compat;
 Backend backend; Backend *_ieee80211=&backend; Interrupt irq; Interrupt *_intrSrc=&irq;
 Interface interface; Interface *_netif=&interface; IOOutputQueue queue;
 AirPortRTW(){interface.owner=this;}
 template<class... T> void setProperty(const char*,T...) {}
 void waitForDiagnosticsIdle(){}; void kickGatedOutput(){};
 bool setLinkStatus(unsigned){return true;}; IOOutputQueue *getOutputQueue(){return &queue;}
 IOReturn restoreAfterSystemWake(); void postSTALinkChanged(bool,uint32_t);
 IOReturn query(bool isSet,void *data){switch(156){
'''
middle = r'''
 default:return kIOReturnUnsupported;}}
};
void Interface::postMessage(unsigned type,void *data,unsigned long length) {
 // CoreWiFi can react synchronously: its first requests must see ready PM,
 // DMA, scan and association state, not the old transaction.
 assert(!owner->_pmTransition && owner->_pmPowerState==kRTW88PowerStateOn);
 assert(!owner->_dmaStopped && !owner->_scanInProgress && !owner->_assocDoneReported);
 ++calls;events.push_back(type);
 if(type==APPLE80211_M_LINK_CHANGED){
   assert(data && length==40);
   auto *raw=(uint8_t*)data; uint32_t typeId,len;
   memcpy(&typeId,raw,4);memcpy(&len,raw+4,4);
   assert(typeId==14 && len==32 && length==8+len);
   memcpy(&last,raw+8,32);
 }
}
'''
post = r'''
int main(){
 // Fixed ABI expectations taken from the native family, independent of the
 // C++ field names. Canary bytes catch a GET accidentally writing past 32.
 AirPortRTW c; uint8_t guarded[40];memset(guarded,0xa5,sizeof(guarded));
 assert(c.query(false,guarded)==0);
 assert(guarded[0]==1 && guarded[16]==1 && guarded[20]==2);
 for(unsigned i=32;i<40;++i)assert(guarded[i]==0xa5);
 c.backend.voluntary=false;assert(c.query(false,guarded)==0);assert(guarded[16]==0);
 c.backend.visible=true;assert(c.query(false,guarded)==0);
 int32_t rssi;memcpy(&rssi,guarded+4,4);assert(guarded[0]==0 && rssi==-55);
 for(unsigned i=16;i<32;++i)assert(guarded[i]==0);
 assert(c.query(true,guarded)==kIOReturnUnsupported);

 AirPortRTW wake;assert(wake.restoreAfterSystemWake()==0);
 assert(wake.backend.powered && wake.irq.enabled && !wake._txStalled);
 assert(wake.interface.events==std::vector<unsigned>({4,1}));
 assert(wake.interface.last.isLinkDown==1 && wake.interface.last.reason==8 && wake.interface.last.flag==0);
 wake.postSTALinkChanged(false,4);assert(wake.interface.last.flag==1 && wake.interface.last.reason==4);
 wake.postSTALinkChanged(true,4);assert(!wake.interface.last.isLinkDown && !wake.interface.last.flag && !wake.interface.last.reason);
 unsigned calls=wake.interface.calls;wake._shutdown=true;wake.postSTALinkChanged(false,0);assert(wake.interface.calls==calls);
 AirPortRTW off;off._pmRadioWasPowered=false;assert(off.restoreAfterSystemWake()==0);
 assert(!off.backend.powered && off.interface.events==std::vector<unsigned>({1}));
 AirPortRTW fail;fail.backend.powerResult=kIOReturnNotReady;
 assert(fail.restoreAfterSystemWake()==kIOReturnNotReady);
 assert(fail.interface.calls==0 && fail._dmaStopped && !fail.pci.master && !fail.irq.enabled);
 AirPortRTW busy;busy._pmTransition=true;assert(busy.restoreAfterSystemWake()==kIOReturnBusy && busy.interface.calls==0);
 std::cout<<"PASS: native link wire offsets, TLV extraction, voluntary/AP disconnect, guarded GET, synchronous wake callbacks, OFF preservation and failed wake fencing\n";
}
'''
program = pre + query + middle + method('void AirPortRTW::postSTALinkChanged(') + method('IOReturn AirPortRTW::restoreAfterSystemWake()') + post
with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory); (p/'test.cpp').write_text(program)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
