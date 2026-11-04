#!/usr/bin/env python3
"""Production link/SSID/BSSID events with inline native status queries.
The macOS menu renderer itself is not part of this host simulation.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/kext/AirPortRTW.cpp').read_text()

def method(signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

methods = method('bool AirPortRTW::setLinkStatus(UInt32 status,') + method('void AirPortRTW::postSTAIdentityChanged(')
pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>
using UInt32=uint32_t;using UInt64=uint64_t;using IOReturn=int;
constexpr unsigned kIONetworkLinkActive=1,kIONetworkLinkValid=2,kIONetworkLinkNoNetworkChange=4;
constexpr int kIO80211NetworkLinkUp=1,kIO80211NetworkLinkDown=2,kIOReturnNotReady=3;
constexpr unsigned APPLE80211_M_ASSOC_DONE=9,APPLE80211_M_SSID_CHANGED=2,APPLE80211_M_BSSID_CHANGED=3;
constexpr bool kOSBooleanTrue=true;
struct OSObject{virtual ~OSObject()=default;};struct IONetworkMedium{};struct OSData{};
void IOLog(const char*,...){}
struct IO80211Controller:OSObject{bool setLinkStatus(UInt32,const IONetworkMedium*,UInt64,OSData*){return true;}};
struct Gate{OSObject*owner=nullptr;bool held=false;
 IOReturn runAction(IOReturn(*fn)(OSObject*,void*,void*,void*,void*),void*a,void*b){assert(!held);held=true;auto r=fn(owner,a,b,nullptr,nullptr);held=false;return r;}};
struct Backend{bool visible=false;unsigned reason=8;unsigned deauthReason(){return reason;}};
struct AirPortRTW;
struct Interface{AirPortRTW*owner=nullptr;bool up=false;std::vector<unsigned>events;
 IOReturn setLinkState(int s,unsigned reason){up=s==kIO80211NetworkLinkUp;assert(up?reason==0:reason==8);return 1;}
 void setLinkQualityMetric(int){}void postMessage(unsigned);
};
struct AirPortRTW:IO80211Controller{
 bool _shutdown=false,_linkUp=false,_assocDoneReported=false,_staIdentityUp=false;unsigned _staIdentityEventPosts=0;
 Gate gate;Backend backend;Backend*_ieee80211=&backend;Interface interface;Interface*_netif=&interface;
 AirPortRTW(){gate.owner=this;interface.owner=this;}
 Gate*getCommandGate(){return &gate;}template<class...T>void setProperty(T...){}
 bool setLinkStatus(UInt32,const IONetworkMedium* =nullptr,UInt64=0,OSData* =nullptr);
 void postSTAIdentityChanged(bool);
};
void Interface::postMessage(unsigned event){
 assert(owner->gate.held);events.push_back(event);
 // A consumer querying immediately sees the new backend and interface
 // state. No old SSID/BSSID should survive a down notification.
 assert(up==owner->backend.visible&&up==owner->_linkUp);
 if(event==2||event==3)assert(owner->_staIdentityUp==up);
}
'''
cases = r'''
int main(){
 AirPortRTW c;c.backend.visible=true;assert(c.setLinkStatus(3));
 assert(c.interface.events==std::vector<unsigned>({9,2,3})&&c._staIdentityEventPosts==1);
 assert(c.setLinkStatus(3));assert(c.interface.events.size()==3); // duplicate key completion
 assert(c.setLinkStatus(3|kIONetworkLinkNoNetworkChange));assert(c.interface.events.size()==3);
 // A real leave clears identity, unlike a connected background scan.
 c.backend.visible=false;assert(c.setLinkStatus(kIONetworkLinkValid));
 assert(c.interface.events==std::vector<unsigned>({9,2,3,2,3})&&!c._assocDoneReported);
 assert(c.setLinkStatus(kIONetworkLinkValid));assert(c.interface.events.size()==5);
 c.backend.visible=true;assert(c.setLinkStatus(3));
 assert(c.interface.events==std::vector<unsigned>({9,2,3,2,3,9,2,3})&&c._staIdentityEventPosts==3);
 c._shutdown=true;assert(!c.setLinkStatus(kIONetworkLinkValid)&&c.interface.events.size()==8);
 AirPortRTW absent;absent._netif=nullptr;assert(absent.setLinkStatus(2)&&absent.interface.events.empty());
 puts("PASS: production link transitions publish SSID/BSSID after coherent native state, retain ASSOC_DONE order, suppress duplicate/unchanged scan events and fence shutdown/missing interface");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.cpp').write_text(pre + methods + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(p / 'test.cpp'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
