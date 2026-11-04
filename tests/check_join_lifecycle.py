#!/usr/bin/env python3
"""Production retry/coalescing + host cancellation, with mocked RF/worker drain."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
b=(root/'src/kext/RTW88IEEE80211.cpp').read_text();c=(root/'src/kext/AirPortRTW.cpp').read_text()
def method(s,sig):
 a=s.index(sig);end=s.index('{',a)+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]+'\n'
methods=''.join(method(b,s) for s in ['bool RTW88IEEE80211::matchesSAETarget(', 'bool RTW88IEEE80211::matchesSAEJoin(', 'bool RTW88IEEE80211::matchesPendingJoin(', 'void RTW88IEEE80211::failJoin(', 'IOReturn RTW88IEEE80211::cmdDisconnect()'])+''.join(method(c,s) for s in ['IOReturn AirPortRTW::handleMenuSAE(', 'IOReturn AirPortRTW::handleDISASSOCIATE()'])
pre=r'''
#include "RTW88AssocWire.hpp"
#include "RTW88WPA3.hpp"
#include "RTW88Roaming.hpp"
#include <cassert>
#include <cstdio>
#include <initializer_list>
using IOReturn=int;using RTW88State=int;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,kIOReturnUnsupported=3,kIOReturnBusy=4;
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_SCANNING=1,RTW88_STATE_AUTHENTICATING=2,RTW88_STATE_ASSOCIATING=3,RTW88_STATE_HANDSHAKING=4,RTW88_STATE_CONNECTED=5;
constexpr int kIONetworkLinkValid=1,kRTW88EventDisconnected=1;
constexpr bool kOSBooleanTrue=true,kOSBooleanFalse=false;
void IOLog(const char*,...){}
struct Timer{void cancelTimeout(){}};struct Parent{void setLinkStatus(int){}};struct Delegate{bool deferWorkerEvent(int,unsigned,unsigned){return false;}void rtw88Event(int,void*){}};
struct RTW88StateResult{int state=0;};
struct RTW88IEEE80211{
 bool _saeMode=false,_disconnectVoluntary=false,_connectCancelled=false,_associatedVisible=false;
 bool _roamScanWorkerPending=false;unsigned _manualScanChannelCount=0;
 bool _enterprise=false,_pmkProvided=false,_awdlOffChannel=false,workerActive=false,deferred=false,abortOK=true;
 unsigned _scanGeneration=0;unsigned _authAttempts=1,starts=0,drains=0,disconnects=0,keyClears=0,staReleases=0,scanAborts=0,_deauthReason=0;
 int _state=RTW88_STATE_IDLE,_scanReturnState=RTW88_STATE_IDLE;
 char _password[64]={};uint8_t _pmk[32]={};
 struct{char ssid[33]={};uint8_t bssid[6]={2,1,2,3,4,5};}_targetBSS;
 Timer timer;Timer*_timer=&timer;Parent*_parent=nullptr;Delegate*_delegate=nullptr;
 void roamTrace(const char*,unsigned=0){}
 bool authenticationCancelled()const{return _connectCancelled;}
 bool matchesSAETarget(const char*,const uint8_t*)const;bool matchesSAEJoin(const char*,const char*,const uint8_t*)const;
 bool matchesPendingJoin(const char*,const uint8_t*,const uint8_t*,bool=false)const;void failJoin(const char*);
 bool associatedVisible()const{return _associatedVisible;}int rawState()const{return _state;}
 void cancelRoamSwitch(){}void clearDeferredJoin(){deferred=false;}
 void cancelAuthentication(){++drains;workerActive=false;_connectCancelled=true;}
 void restoreSTAChannelAfterAWDL(){_awdlOffChannel=false;}
 bool abortActiveScan(bool){++scanAborts;if(abortOK)_state=5;return abortOK;}
 void clearKeys(){assert(!workerActive);++keyClears;_saeMode=false;memset(_password,0,64);}
 void clearAssocRsnIE(){}void releaseSta(){assert(!workerActive);++staReleases;}
 void doDisconnect(){assert(!workerActive);++disconnects;clearKeys();releaseSta();_state=0;_associatedVisible=false;_scanReturnState=0;}
 IOReturn cmdGetState(RTW88StateResult*r){r->state=_associatedVisible?5:_state;return 0;}
 IOReturn cmdDisconnect();
 bool bssOffersPSKOnly(const char*,const uint8_t*){return false;}
 bool matchesPSKPasswordJoin(const char*,const char*,const uint8_t*){return false;}
 IOReturn cmdConnect(const char*,const char*,const uint8_t*,const uint8_t*,bool){assert(false);return 0;}
 IOReturn cmdConnectSAE(const char*s,const char*p,const uint8_t*){++starts;_state=2;_connectCancelled=false;_saeMode=true;strcpy(_targetBSS.ssid,s);strcpy(_password,p);return 0;}
};
struct AirPortRTW{
 RTW88IEEE80211*_ieee80211;bool _shutdown=false,_assocDoneReported=false,_rsnHandshakeReported=false;
 unsigned _authLower=0,_authUpper=0;
 bool roamingActionsAllowed(){return true;}
 template<class...T>void setProperty(T...){}
 IOReturn handleMenuSAE(const RTW88AssocWire::Personal&);IOReturn handleDISASSOCIATE();
};
'''
cases=r'''
int main(){
 RTW88AssocWire::Personal r{};r.lower=1;r.cipher=10;r.upper=4096;r.ssidLength=4;r.keyLength=8;
 memcpy(r.ssid,"test",4);memcpy(r.key,"password",8);
 RTW88IEEE80211 b;AirPortRTW a{&b};assert(a.handleMenuSAE(r)==0&&b.starts==1);
 // Identical LIVE retries coalesce. A new password must actually restart.
 assert(a.handleMenuSAE(r)==0&&b.starts==1);r.key[0]='P';
 assert(a.handleMenuSAE(r)==0&&b.starts==2&&b.disconnects==1&&!strcmp(b._password,"Password"));
 // Regression: failJoin left target metadata, and Beta6 reported success
 // without starting anything on this exact same request.
 b.failJoin("auth-retry-limit");assert(b._state==0&&b._connectCancelled);
 assert(!b.matchesSAETarget("test",nullptr));assert(a.handleMenuSAE(r)==0&&b.starts==3);
 // Every incomplete state can be explicitly aborted, for WPA2 and WPA3.
 for(bool sae:{false,true})for(int state:{2,3,4}){
  RTW88IEEE80211 x;x._saeMode=sae;x._state=state;x.workerActive=true;x.deferred=true;strcpy(x._password,"secret");
  AirPortRTW ctl{&x};assert(ctl.handleDISASSOCIATE()==0);
  assert(x.drains==1&&x.disconnects==1&&x.keyClears==1&&x.staReleases==1&&!x.workerActive&&!x.deferred&&!x._password[0]);
  assert(x._state==0&&!x._associatedVisible&&!x._saeMode);
 }
 // Idle after a failure must still drain and remove retained CAM/STA state.
 b.failJoin("assoc-timeout");b.workerActive=true;
 assert(b.cmdDisconnect()==0&&b.keyClears==2&&b.staReleases==2&&!b._saeMode);
 // Failed connected-scan abort keeps ownership; never free STA under worker.
 RTW88IEEE80211 scan;scan._state=1;scan._associatedVisible=true;scan._scanReturnState=5;scan.abortOK=false;
 assert(scan.cmdDisconnect()==kIOReturnBusy&&!scan.keyClears&&!scan.drains);
 scan.abortOK=true;assert(scan.cmdDisconnect()==0&&scan.scanAborts==2&&scan.disconnects==1);
 // Preserve disconnected scan completion (including the existing frontend ACK).
 RTW88IEEE80211 standalone;standalone._state=1;standalone.deferred=true;
 assert(standalone.cmdDisconnect()==0&&standalone._state==1&&!standalone.scanAborts&&!standalone.deferred);
 // WPA2/open/Enterprise coalescing cannot treat a failed/cancelled/SAE attempt
 // as a live duplicate; a new target is never coalesced.
 RTW88IEEE80211 w;strcpy(w._targetBSS.ssid,"test");w._state=2;w._pmkProvided=true;memset(w._pmk,0x55,32);
 assert(w.matchesPendingJoin("test",nullptr,w._pmk));
 assert(!w.matchesPendingJoin("other",nullptr,w._pmk));
 w._state=0;assert(!w.matchesPendingJoin("test",nullptr,w._pmk));w._state=2;w._connectCancelled=true;
 assert(!w.matchesPendingJoin("test",nullptr,w._pmk));w._connectCancelled=false;w._saeMode=true;
 assert(!w.matchesPendingJoin("test",nullptr,w._pmk));
 puts("PASS: production failed-SAE retry, password changes, live WPA2/SAE coalescing, AUTH/ASSOC/handshake abort, worker-before-key cleanup, idle CAM/STA cleanup and scan ownership");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
