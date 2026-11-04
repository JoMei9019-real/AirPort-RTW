#!/usr/bin/env python3
"""Production native status/result replies and completed SAE rejection event.

Apple delivery is mocked with synchronous queries during ASSOC_DONE. This is
not a measurement of airportd's timeout or UI behavior on real macOS.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
backend = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
controller = (root / 'src/kext/AirPortRTW.cpp').read_text()

def method(source, signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

def case(name):
    start = controller.index('    case ' + name + ':')
    end = controller.index('\n    case ', start + 1)
    return controller[start:end] + '\n'

pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
using IOReturn=int;
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_SCANNING=1,RTW88_STATE_AUTHENTICATING=2,RTW88_STATE_CONNECTED=5;
constexpr int kIOReturnSuccess=0,kIOReturnUnsupported=1,kIOReturnNotReady=2;
constexpr int APPLE80211_IOC_ASSOCIATE_RESULT=21,APPLE80211_IOC_ASSOCIATION_STATUS=50,APPLE80211_VERSION=1;
constexpr unsigned APPLE80211_STATUS_SUCCESS=0,APPLE80211_STATUS_UNAVAILABLE=0xffff,APPLE80211_STATUS_CHALLENGE_FAILURE=15;
constexpr unsigned APPLE80211_RESULT_SUCCESS=1,APPLE80211_RESULT_UNSPECIFIED_FAILURE=2,APPLE80211_RESULT_CHALLENGE_FAILURE=8;
constexpr int kRTW88EventDisconnected=3,APPLE80211_M_ASSOC_DONE=9;
constexpr bool kOSBooleanTrue=true;
struct apple80211_assoc_status_data{uint32_t version,status;};
struct apple80211_assoc_result_data{uint32_t version,result;};
struct RTW88StateResult{int state=0;};
struct RTW88IEEE80211{
 int _state=0;bool _associatedVisible=false,_saeMode=true,cancelled=true;
 struct{unsigned error=0x4000f;}_sae;
 bool joinCancelled()const{return cancelled;}
 unsigned saeRejectionStatus()const;
 unsigned deauthReason()const{return 0;}
 int cmdGetState(RTW88StateResult*r){r->state=_associatedVisible?5:_state;return 0;}
};
struct AirPortRTW;
struct Interface{AirPortRTW*owner=nullptr;unsigned posts=0;void postMessage(unsigned);};
struct AirPortRTW{
 RTW88IEEE80211 backend;RTW88IEEE80211*_ieee80211=&backend;
 Interface interface;Interface*_netif=&interface;
 bool _shutdown=false,_assocDoneReported=false;unsigned failureStatus=0;
 std::vector<unsigned>events;
 AirPortRTW(){interface.owner=this;}
 void setProperty(const char*name,uint64_t v,unsigned){if(!strcmp(name,"STA_ASSOC_FAILURE_STATUS"))failureStatus=unsigned(v);}
 void setProperty(const char*,bool){}
 void postSTALinkChanged(bool up,unsigned){assert(!up);events.push_back(4);}
 void postSTAJoinFailure();
 IOReturn query(int request_number,bool isSet,void*data){switch(request_number){
'''
middle = r'''
 default:return kIOReturnUnsupported;}}
 void disconnected(){switch(kRTW88EventDisconnected){
'''
post = r'''
 default:assert(false);}}
};
void Interface::postMessage(unsigned message){
 assert(message==APPLE80211_M_ASSOC_DONE);++posts;owner->events.push_back(message);
 assert(owner->_assocDoneReported&&!owner->backend._associatedVisible);
 // Native consumers can query the outcome immediately from the notification.
 apple80211_assoc_status_data status{};apple80211_assoc_result_data result{};
 assert(owner->query(50,false,&status)==0&&status.version==1&&status.status==15);
 assert(owner->query(21,false,&result)==0&&result.version==1&&result.result==8);
}
'''
cases = r'''
int main(){
 AirPortRTW c;
 struct Guard{apple80211_assoc_result_data result;uint8_t canary[16];}guard{};
 memset(guard.canary,0xa5,sizeof(guard.canary));
 assert(c.query(21,false,&guard.result)==0&&guard.result.version==1&&guard.result.result==8);
 for(auto byte:guard.canary)assert(byte==0xa5);
 c.disconnected();assert(c.interface.posts==1&&c.failureStatus==15);
 assert(c.events==std::vector<unsigned>({4,9}));
 c.disconnected();assert(c.interface.posts==1); // failure completion is single-shot
 apple80211_assoc_status_data status{};apple80211_assoc_result_data result{};
 for(unsigned code:{1u,13u,77u}){
  c.backend._sae.error=0x40000|code;
  assert(c.query(50,false,&status)==0&&status.status==code);
  assert(c.query(21,false,&result)==0&&result.result==2);
 }
 // A newer pending join, scan, visible link or manual/crypto cleanup cannot
 // inherit the previous rejection. The native GET remains pending until ready.
 for(unsigned mode=0;mode<6;++mode){
  AirPortRTW pending;
  if(mode==0)pending.backend._state=2;
  if(mode==1)pending.backend._state=1;
  if(mode==2)pending.backend.cancelled=false;
  if(mode==3)pending.backend._saeMode=false;
  if(mode==4)pending.backend._sae.error=0;
  if(mode==5)pending.backend._sae.error=0x20000;
  assert(pending.backend.saeRejectionStatus()==0xffff);
  assert(pending.query(21,false,&result)==kIOReturnNotReady);
  assert(pending.query(50,false,&status)==0&&status.status==0xffff);
  pending.postSTAJoinFailure();assert(!pending.interface.posts);
 }
 AirPortRTW connected;connected.backend._state=5;connected.backend._associatedVisible=true;
 assert(connected.backend.saeRejectionStatus()==0xffff);
 assert(connected.query(50,false,&status)==0&&status.status==0);
 assert(connected.query(21,false,&result)==0&&result.result==1);
 connected.postSTAJoinFailure();assert(!connected.interface.posts);
 assert(c.query(50,true,&status)==kIOReturnUnsupported&&c.query(21,true,&result)==kIOReturnUnsupported);
 AirPortRTW stopped;stopped._shutdown=true;stopped.postSTAJoinFailure();assert(!stopped.interface.posts);
 stopped._shutdown=false;stopped._netif=nullptr;stopped.postSTAJoinFailure();assert(!stopped.interface.posts);
 stopped._netif=&stopped.interface;stopped._ieee80211=nullptr;stopped.postSTAJoinFailure();assert(!stopped.interface.posts);
 puts("PASS: production terminal SAE status/result, one failure ASSOC_DONE with synchronous native queries, wire canaries, pending/new/manual/success fences and shutdown/null guards");
}
'''

program = (pre + case('APPLE80211_IOC_ASSOCIATION_STATUS') +
           case('APPLE80211_IOC_ASSOCIATE_RESULT') + middle +
           case('kRTW88EventDisconnected') + post +
           method(backend, 'unsigned RTW88IEEE80211::saeRejectionStatus()') +
           method(controller, 'void AirPortRTW::postSTAJoinFailure()') + cases)
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.cpp').write_text(program)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(p / 'test.cpp'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
