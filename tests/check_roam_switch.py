#!/usr/bin/env python3
"""Execute production switch transaction with mocked association/firmware calls."""
import ast, os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/kext/RTW88IEEE80211.cpp').read_text()
def method(signature):
 start=s.index(signature);p=s.index('{',start);end=p+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]+'\n'
tree=ast.parse((root/'tests/check_roaming.py').read_text())
pre=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='pre' for t in n.targets))
pre=pre.replace('#include "RTW88Roaming.hpp"','#include "RTW88RoamSwitch.hpp"')
extra=r'''
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,kIOReturnBusy=3,kIOReturnNotFound=4,kIOReturnUnsupported=5,kIOReturnError=6;
constexpr int NL80211_NUM_BANDS=1,IEEE80211_CHAN_DISABLED=1,IEEE80211_CHAN_NO_IR=2,IEEE80211_CHAN_RADAR=4,RTW88_STATE_IDLE=0;
void IOLockLock(void*){}void IOLockUnlock(void*){}
struct Channel{int hw_value=6,center_freq=2437,flags=0;};
struct Band{int n_channels=1;Channel channels[1];};struct Wiphy{Band*bands[1];};struct Hw{Wiphy*wiphy;};
struct RTW88BSS{
 uint8_t bssid[6]={2,9,8,7,6,1},ssid_len=4,channel=6;
 char ssid[33]="Test";int rssi=-45,freq=2437;
 uint64_t observedMs=1000,beaconObservedMs=0;uint32_t capabilities=0x11;uint8_t ies[512]={};uint16_t ies_len=0;RTW88BSS *next=nullptr;
};
'''
pre=pre.replace('struct RTW88IEEE80211 {',extra+r'''
struct RTW88IEEE80211 {
 RTW88RoamSwitch::Transaction _roamSwitch;
 bool _roamSwitchEnabled=true,_roamSwitchInternal=false;
 bool _authenticationWorkerActive=false,_connectCancelled=false;
 uint64_t _roamSwitchLast=0;uint32_t _roamSwitchResult=0;
 unsigned _roamReason=0;uint32_t _roamRequestReturn=0,_deauthReason=0,_manualScanChannelCount=0;
 uint64_t _roamNeighborAge=0,_roamScanAge=0,_roamScanLast=0;
 uint8_t _roamDiagTarget[6]={};int _roamTargetRSSI=0;uint32_t _roamTargetChannel=0,_roamChannelFlags=0;
 uint8_t _roamRecommended[6]={};bool _roamTargetFromScan=false;
 unsigned roamChannelReason(unsigned,unsigned,uint32_t * =nullptr)const;
 unsigned roamBSSReason(const RTW88BSS&,uint64_t)const;IOReturn roamControlReady();
 IOReturn validateRoam(const uint8_t*,uint64_t,bool);void beginRoamTest(const uint8_t*);
 IOReturn roamDecision(unsigned,IOReturn);IOReturn checkRoam(const uint8_t*,uint64_t);
 uint8_t _pmk[32]={7};void *_bssLock=nullptr;RTW88BSS *_bssList=nullptr;Hw *_hw=nullptr;
 unsigned disconnects=0,joins=0,drains=0;int joinResult=0;
 void cancelAuthentication(){++drains;}
 void doDisconnect(){++disconnects;_state=0;_associatedVisible=false;_ptkConf=_gtkConf=nullptr;memset(_pmk,0,32);resetRoamingState();}
 int cmdConnect(const char *ssid,const char*,const uint8_t *pmk,const uint8_t *ap,bool){
  assert(!strcmp(ssid,"Test")&&pmk[0]==7);++joins;
  memcpy(_targetBSS.bssid,ap,6);memcpy(_pmk,pmk,32);_state=2;return joinResult;
 }
 IOReturn requestRoam(const uint8_t*,uint64_t);void cancelRoamSwitch();
''')
pre=pre.replace('void roamSwitchTick(uint64_t){}','void roamSwitchTick(uint64_t);')
methods=''.join(method(n) for n in ('void RTW88IEEE80211::resetRoamingState()', 'bool RTW88IEEE80211::roamingActionsReady() const','void RTW88IEEE80211::beginRoamTest(','IOReturn RTW88IEEE80211::roamDecision(','unsigned RTW88IEEE80211::roamChannelReason(','unsigned RTW88IEEE80211::roamBSSReason(','IOReturn RTW88IEEE80211::roamControlReady(','IOReturn RTW88IEEE80211::validateRoam(','IOReturn RTW88IEEE80211::checkRoam(','void RTW88IEEE80211::cancelRoamSwitch()','IOReturn RTW88IEEE80211::requestRoam(','void RTW88IEEE80211::roamSwitchTick('))
cases=r'''
void keyed(RTW88IEEE80211 &b){b._state=5;b._associatedVisible=true;b._ptkConf=b._gtkConf=&b;}
void erased(RTW88IEEE80211 &b){assert(!b._roamSwitch.phase);for(auto v:b._roamSwitch.pmk)assert(!v);}
int main(){
 RTW88IEEE80211 b;Band band;Wiphy w{{&band}};Hw hw{&w};RTW88BSS candidate;
 uint8_t rsn[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
 memcpy(candidate.ies,rsn,sizeof(rsn));candidate.ies_len=sizeof(rsn);
 memcpy(b._targetBSS.ies,rsn,sizeof(rsn));b._targetBSS.ies_len=sizeof(rsn);
 b._hw=&hw;b._bssList=&candidate;b._roamingAssistEnabled=true;b._roamingCapsValid=true;
 b._roaming.neighbors.count=1;b._roaming.neighborsMs=1000;
 memcpy(b._roaming.neighbors.entries[0].bssid,candidate.bssid,6);b._roaming.neighbors.entries[0].channel=6;
 uint8_t oldAP[6];memcpy(oldAP,b._targetBSS.bssid,6);
 assert(b.requestRoam(oldAP,1100)==kIOReturnBadArgument);
 b._roamSwitchEnabled=false;assert(b.requestRoam(candidate.bssid,1100)==kIOReturnNotReady);b._roamSwitchEnabled=true;
 candidate.observedMs=1;assert(b.requestRoam(candidate.bssid,31000)==kIOReturnNotFound);candidate.observedMs=1000;
 candidate.ssid[0]='X';assert(b.requestRoam(candidate.bssid,1100)==kIOReturnNotFound);candidate.ssid[0]='T';
 candidate.ies[sizeof(rsn)-2]=0x40;assert(b.requestRoam(candidate.bssid,1100)==kIOReturnNotFound);candidate.ies[sizeof(rsn)-2]=0;
 band.channels[0].flags=IEEE80211_CHAN_RADAR;assert(b.requestRoam(candidate.bssid,1100)==kIOReturnNotFound);band.channels[0].flags=0;
 assert(!b.disconnects&&!b.joins);
 assert(b.requestRoam(candidate.bssid,1100)==0&&b._roamSwitch.phase==1&&b.joins==1&&b.disconnects==1);
 assert(b._roamSwitch.pmk[0]==7&&b._pmk[0]==7&&!b._roamSwitchInternal);
 b.roamSwitchTick(1200);assert(b.joins==1);
 keyed(b);b.roamSwitchTick(1300);assert(b._roamSwitchResult==3);erased(b);
 // Reset fixture for a target failure followed by one successful fallback.
 memcpy(b._targetBSS.bssid,oldAP,6);b._roamingCapsValid=true;b._roaming.neighbors.count=1;
 b._roaming.neighborsMs=candidate.observedMs=70000;
 memcpy(b._roaming.neighbors.entries[0].bssid,candidate.bssid,6);b._roaming.neighbors.entries[0].channel=6;
 assert(b.requestRoam(candidate.bssid,70100)==0);
 b._state=0;b.roamSwitchTick(70200);assert(b._roamSwitch.phase==2&&b._roamSwitchResult==2&&b.joins==3);
 assert(!memcmp(b._targetBSS.bssid,oldAP,6));keyed(b);b.roamSwitchTick(70300);
 assert(b._roamSwitchResult==4);erased(b);
 // Timeout and fallback timeout terminate; no recurring reconnect loop.
 b._roamSwitch.phase=1;b._roamSwitch.started=100000;b._roamSwitch.pmk[0]=7;
 strcpy(b._roamSwitch.ssid,"Test");memcpy(b._roamSwitch.oldAP,oldAP,6);b._state=2;b._associatedVisible=false;
 b._authenticationWorkerActive=true;
 unsigned prior=b.joins;b.roamSwitchTick(115000);assert(b.joins==prior&&b._connectCancelled);
 b._authenticationWorkerActive=false;
 b.roamSwitchTick(115000);assert(b._roamSwitch.phase==2);
 b.roamSwitchTick(130000);assert(b._roamSwitchResult==5);erased(b);
 unsigned joins=b.joins;b.roamSwitchTick(150000);assert(b.joins==joins);
 b._roamSwitch.phase=1;b._roamSwitch.pmk[0]=8;b.parent.allowed=false;
 b.roamSwitchTick(160000);assert(b._roamSwitchResult==6);erased(b);
 assert(!RTW88RoamSwitch::security(rsn,sizeof(rsn)-1));
 puts("PASS: production AP-switch eligibility, fresh scan/security/regulatory gates, key snapshot, success, one fallback, deadlines and PM cancellation");
}
'''
c=(root/'src/kext/AirPortRTW.cpp').read_text()
assert 'clientHasPrivilege(current_task(),kIOClientPrivilegeAdministrator)' in c
assert 'target->getLength()!=6' in c and '_workLoop->runAction' in c
assert 'cancelRoamSwitch();' in method('IOReturn RTW88IEEE80211::cmdDisconnect()')
assert 'cancelRoamSwitch();' in method('IOReturn RTW88IEEE80211::cmdPowerOffGated()')
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'t.cpp').write_text(pre+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
 subprocess.run([str(p/'t')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
