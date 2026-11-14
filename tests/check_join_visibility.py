#!/usr/bin/env python3
"""Production join/association and Apple status queries during network changes.
RF, worker scheduling and peer capability parsing are mocked, not WPA crypto.
The separate handshake tests cover actual key/M4 completion.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
b = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
c = (root / 'src/kext/AirPortRTW.cpp').read_text()
h = (root / 'src/kext/RTW88IEEE80211.hpp').read_text()
u = (root / 'src/kext/RTW88UserClient.hpp').read_text()

def method(source, signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

records = h[h.index('struct RTW88BSS {'):h.index('/* ------------------------------------------------------------------ */', h.index('struct RTW88BSS {'))]
records += u[u.index('struct RTW88StateResult {'):u.index('/* ------------------------------------------------------------------ */', u.index('struct RTW88StateResult {'))]
methods = ''.join(method(b, sig) for sig in (
    'bool RTW88IEEE80211::matchesPendingJoin(',
    'bool RTW88IEEE80211::matchesSAETarget(',
    'bool RTW88IEEE80211::matchesSAEJoin(',
    'bool RTW88IEEE80211::matchesPSKPasswordJoin(',
    'bool RTW88IEEE80211::bssOffersPSKOnly(',
    'bool RTW88IEEE80211::cachedJoinTargetReady(',
    'IOReturn RTW88IEEE80211::cmdConnect(',
    'IOReturn RTW88IEEE80211::cmdDisconnect()',
    'void RTW88IEEE80211::clearDeferredJoin()',
    'void RTW88IEEE80211::resumeDeferredJoin()',
    'void RTW88IEEE80211::processAssocResponse(',
    'IOReturn RTW88IEEE80211::cmdGetState(',
    'IOReturn RTW88IEEE80211::copyCurrentBSS('))
methods += ''.join(method(c, sig) for sig in (
    'IOReturn AirPortRTW::handleSSID(', 'IOReturn AirPortRTW::handleSTATE(',
    'IOReturn AirPortRTW::handleMenuSAE('))

pre = r'''
#include "RTW88MgmtValidation.hpp"
#include "RTW88Enterprise.hpp"
#include "RTW88WPA3.hpp"
#include "RTW88AssocWire.hpp"
#include "RTW88Roaming.hpp"
#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using IOReturn=int;using RTW88State=int;using u32=uint32_t;
enum {RTW88_STATE_IDLE,RTW88_STATE_SCANNING,RTW88_STATE_AUTHENTICATING,
 RTW88_STATE_ASSOCIATING,RTW88_STATE_HANDSHAKING,RTW88_STATE_CONNECTED};
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnBusy=2,kIOReturnNotReady=3,
 kIOReturnUnsupported=4,kIOReturnNotFound=5};
enum {APPLE80211_S_INIT,APPLE80211_S_SCAN,APPLE80211_S_AUTH,APPLE80211_S_ASSOC,APPLE80211_S_RUN};
constexpr unsigned APPLE80211_VERSION=1,APPLE80211_MAX_SSID_LEN=32,ETH_ALEN=6;
constexpr int kIONetworkLinkValid=1,kIONetworkLinkActive=2,kMillisecondScale=1;
constexpr int kRTW88EventAssocDone=1,BSS_CHANGED_ASSOC=1,BSS_CHANGED_QOS=2;
enum nl80211_band {NL80211_BAND_2GHZ,NL80211_BAND_5GHZ};
constexpr unsigned NL80211_NUM_BANDS=2,IEEE80211_CHAN_DISABLED=1,IEEE80211_CHAN_NO_IR=2,IEEE80211_CHAN_RADAR=4;
constexpr bool kOSBooleanTrue=true,kOSBooleanFalse=false;
constexpr int IEEE80211_STA_RX_BW_20=0,IEEE80211_STA_RX_BW_40=1,IEEE80211_STA_RX_BW_80=2;
constexpr int IEEE80211_HT_CAP_SUP_WIDTH_20_40=2,IEEE80211_HT_CAP_SGI_40=64,IEEE80211_HT_CAP_DSSSCCK40=4096;
constexpr uint32_t WLAN_CIPHER_SUITE_CCMP=0xfac04;
constexpr uint8_t WLAN_EID_RSN=48;
void IOLog(const char*,...){}
void IOLockLock(void*){}void IOLockUnlock(void*){}
void IOFree(void*p,size_t){free(p);}void*IOMallocZero(size_t n){return calloc(1,n);}
size_t strlcpy(char*d,const char*s,size_t n){size_t z=strlen(s);if(n){size_t m=z<n-1?z:n-1;memcpy(d,s,m);d[m]=0;}return z;}
void clock_interval_to_deadline(int,int,uint64_t*d){*d=8000;}
uint64_t simulatedNow=7000000000ULL;uint64_t mach_absolute_time(){return simulatedNow;}void absolutetime_to_nanoseconds(uint64_t t,uint64_t*n){*n=t;}
unsigned scheduled=0;void thread_call_enter(void*){++scheduled;}
void derivePMK(const uint8_t*,const uint8_t*,unsigned,uint8_t*p){memset(p,0x55,32);}
bool rtw88RsnSelectCcmpPsk(const uint8_t*,unsigned,uint32_t*,uint32_t*){return false;}
void rtw88_get_fw_version(void*,uint16_t*v,uint8_t*s){*v=1;*s=0;}
void rtw88_get_chip_name(void*,char*p,size_t n){strlcpy(p,"mock",n);}
void rtw88_get_stats(void*,uint32_t*t,uint32_t*r){*t=*r=0;}
struct HT{bool ht_supported=false;struct{uint8_t rx_mask[10]={};}mcs;uint16_t cap=0;};
struct VHT{bool vht_supported=false;uint32_t cap=0;struct{uint16_t rx_mcs_map=0;}vht_mcs;};
struct ieee80211_sta{uint8_t addr[6]={};unsigned aid=0;bool wme=false;
 struct{unsigned supp_rates[2]={},bandwidth=0;HT ht_cap;VHT vht_cap;}deflink;};
struct ieee80211_bss_conf{bool assoc=false,qos=false;unsigned aid=0;uint8_t bssid_buf[6]={};uint8_t*bssid=nullptr;};
struct Vif{ieee80211_bss_conf bss_conf;struct{bool assoc=false;unsigned aid=0;}cfg;};
struct Hw;struct Ops{int(*sta_add)(Hw*,Vif*,ieee80211_sta*)=nullptr;
 void(*bss_info_changed)(Hw*,Vif*,ieee80211_bss_conf*,int)=nullptr;void(*cancel_hw_scan)(Hw*,Vif*)=nullptr;
 void*hw_scan=nullptr;};
struct ieee80211_channel{unsigned hw_value=6,flags=0;};
struct SupportedBand{ieee80211_channel*channels=nullptr;int n_channels=0;};
struct Hw{Ops ops_;Ops*ops=&ops_;unsigned sta_data_size=0;struct Wiphy{SupportedBand*bands[2]={};}wiphy_;Wiphy*wiphy=&wiphy_;};
/* Test fixture for Beta 2's association-completion coexistence hook.
 * Production implementation lives in the rtw88 compatibility layer. */
unsigned coexJoinSuccessNotifications = 0;
void rtw88_coex_join_end(Hw*, bool successful) {
 assert(successful);
 ++coexJoinSuccessNotifications;
}
bool rtw88_hw_scan_supported(Hw*){return false;}
struct rtw88_peer_caps{bool have_ht=false,have_vht=false;HT ht;VHT vht;};
void rtw88_parse_peer_caps(const uint8_t*,unsigned,rtw88_peer_caps*){}
void rtw88_restrict_peer_caps(rtw88_peer_caps*,void*){}void rtw88_register_sta(Vif*,ieee80211_sta*){}
uint16_t le16_to_cpu(uint16_t x){return x;}
struct sk_buff{uint8_t data[30]={};unsigned len=30;bool freed=false;};
void kfree_skb(sk_buff*p){assert(!p->freed);p->freed=true;}
struct Timer{bool armed=false;void cancelTimeout(){armed=false;}void wakeAtTime(uint64_t){armed=true;}void setTimeoutMS(int){armed=true;}};
struct Parent{bool up=false;unsigned ups=0,downs=0;
 int addressResult=0;RTW88AssocWire::StationAddress station;
 IOReturn prepareJoinStationAddress(const RTW88AssocWire::StationAddress &request){
  station=request;return addressResult;}
 void setLinkStatus(unsigned s){up=(s&kIONetworkLinkActive);up?++ups:++downs;}};
struct Delegate{unsigned assoc=0;void rtw88Event(int,void*){++assoc;}};
'''
declarations = r'''
struct RTW88IEEE80211{
 bool _associatedVisible=false,_powered=true,_connectCancelled=false,_disconnectVoluntary=false,_awdlOffChannel=false;
 bool _roamScanWorkerPending=false,_roamSwitchInternal=false,_manualScanAbort=false;
 uint64_t _rxNoiseSample=0;
 bool _deferredConnectPending=false,_deferredPMKValid=false,_deferredBSSIDValid=false,_deferredExternalSupplicant=false,_deferredSAE=false;
 char _deferredSSID[33]={},_deferredPassword[64]={};uint8_t _deferredPMK[32]={},_deferredBSSID[6]={};
 RTW88AssocWire::StationAddress _deferredStationAddress;
 bool _saeMode=false,_enterprise=false,_externalSupplicant=false,_pmkProvided=false,_wpa2=true,_curBssTim=false;
 bool abortOK=true;unsigned _manualScanChannelCount=0,_authAttempts=0,_deauthReason=0,_assocAID=0,_connChanWidth=20,_scanGeneration=7;
 int _state=RTW88_STATE_IDLE,_scanReturnState=RTW88_STATE_IDLE,_rssi=-50;
 uint8_t _macAddr[6]={2,1,2,3,4,5},_pmk[32]={},_assocRsnIE[258]={};uint16_t _assocRsnIELen=0;
 char _password[64]={};size_t _staAllocSize=0;RTW88BSS _targetBSS={},*_bssList=nullptr;
 void*_bssLock=this,*_connectTC=this,*_rtwdev=nullptr;
 Hw hw;Hw*_hw=&hw;Vif vif;Vif*_vif=&vif;ieee80211_sta sta;ieee80211_sta*_sta=nullptr;
 Parent parent;Parent*_parent=&parent;Delegate delegate;Delegate*_delegate=&delegate;Timer timer;Timer*_timer=&timer;
 unsigned failures=0,drains=0;
 bool authenticationCancelled()const{return _connectCancelled;}
 int rawState()const{return _state;}bool associatedVisible()const{return _associatedVisible;}
 void roamTrace(const char*,unsigned=0){}void cancelRoamSwitch(){}
 void clearKeys(){_saeMode=false;}void releaseSta(){_sta=nullptr;}
 void clearAssocRsnIE(){_assocRsnIELen=0;}bool htAllowed(){return true;}void startTxAggregation(){}
 void clearDeferredJoin();
 void cancelAuthentication(){++drains;_connectCancelled=true;}
 void restoreSTAChannelAfterAWDL(){_awdlOffChannel=false;}
 bool abortActiveScan(bool){if(abortOK){_state=RTW88_STATE_CONNECTED;_scanReturnState=0;}return abortOK;}
 void failJoin(const char*){++failures;_state=RTW88_STATE_IDLE;_associatedVisible=false;_connectCancelled=true;}
 void doDisconnect(){clearKeys();releaseSta();_state=RTW88_STATE_IDLE;_associatedVisible=false;_parent->setLinkStatus(kIONetworkLinkValid);}
 IOReturn cmdConnect(const char*,const char*,const uint8_t*,const uint8_t*,bool,bool=false,
                     const RTW88AssocWire::StationAddress & = {});
 IOReturn cmdConnectSAE(const char*s,const char*p,const uint8_t*b,const RTW88AssocWire::StationAddress &station){
  clearAssocRsnIE();return cmdConnect(s,p,nullptr,b,false,true,station);}
 bool bssOffersPSKOnly(const char*,const uint8_t*);
 bool cachedJoinTargetReady(const char*,const uint8_t*,bool);
 bool matchesPendingJoin(const char*,const uint8_t*,const uint8_t*,bool=false)const;
 bool matchesSAETarget(const char*,const uint8_t*)const;bool matchesSAEJoin(const char*,const char*,const uint8_t*)const;
 bool matchesPSKPasswordJoin(const char*,const char*,const uint8_t*)const;void resumeDeferredJoin();
 IOReturn cmdDisconnect();void processAssocResponse(sk_buff*);IOReturn cmdGetState(RTW88StateResult*);IOReturn copyCurrentBSS(RTW88BSS*);
};
struct apple80211_ssid_data{unsigned version=0,ssid_len=0;uint8_t ssid_bytes[32]={};};
struct apple80211_state_data{unsigned version=0,state=0;};
struct AirPortRTW{RTW88IEEE80211*_ieee80211;template<class...T>void setProperty(T...){}
 bool _shutdown=false,_assocDoneReported=false,_rsnHandshakeReported=false;unsigned _authLower=0,_authUpper=0;
 bool roamingActionsAllowed(){return true;}IOReturn handleMenuSAE(const RTW88AssocWire::Personal&);
 bool matchesJoinStationAddress(const RTW88AssocWire::StationAddress &){return true;}
 IOReturn handleSSID(bool,apple80211_ssid_data*);IOReturn handleSTATE(apple80211_state_data*);};
'''
cases = r'''
RTW88BSS network(const char*s,unsigned id){RTW88BSS n={};strlcpy(n.ssid,s,sizeof(n.ssid));n.ssid_len=strlen(s);n.bssid[0]=2;n.bssid[5]=id;n.channel=6;n.rssi=-45;n.cipher=WLAN_CIPHER_SUITE_CCMP;return n;}
sk_buff response(RTW88IEEE80211&b,unsigned status=0){sk_buff s;s.data[0]=0x10;
 memcpy(s.data+4,b._macAddr,6);memcpy(s.data+10,b._targetBSS.bssid,6);memcpy(s.data+16,b._targetBSS.bssid,6);
 s.data[26]=status;s.data[28]=1;return s;}
void queries(RTW88IEEE80211&b,bool run,unsigned appleState){AirPortRTW a{&b};RTW88StateResult r={};
 assert(b.cmdGetState(&r)==0);assert((r.state==RTW88_STATE_CONNECTED)==run);
 apple80211_state_data st;assert(a.handleSTATE(&st)==0&&st.state==appleState);
 apple80211_ssid_data ssid;assert((a.handleSSID(false,&ssid)==0)==run);
 RTW88BSS current;assert((b.copyCurrentBSS(&current)==0)==run);
 if(run){assert(ssid.ssid_len==b._targetBSS.ssid_len&&!memcmp(ssid.ssid_bytes,b._targetBSS.ssid,ssid.ssid_len));assert(!memcmp(current.bssid,b._targetBSS.bssid,6));}
}
int main(){
 // A deferred request carries its address to the authentication boundary.
 // If the hardware rejects the address, no authentication worker starts.
 {
  using Mode = RTW88AssocWire::StationAddress::Mode;
  RTW88IEEE80211 b;auto target=network("private",3);b._bssList=&target;
  b._rxNoiseSample=1;
  b._state=RTW88_STATE_SCANNING;
  uint8_t pmk[32]={};
  const RTW88AssocWire::StationAddress station{Mode::Private,{0x02,1,2,3,4,5}};
  assert(b.cmdConnect("private",nullptr,pmk,nullptr,false,false,station)==0);
  assert(b.parent.station.mode==Mode::Unspecified&&b._rxNoiseSample==1);
  b._state=RTW88_STATE_IDLE;
  const unsigned before=scheduled;
  b.parent.addressResult=kIOReturnBusy;
  b.resumeDeferredJoin();
  assert(scheduled==before&&b.failures==1&&!b._deferredConnectPending&&!b._rxNoiseSample);
  assert(b.parent.station.mode==Mode::Private&&!memcmp(b.parent.station.bytes,station.bytes,6));
  assert(b._deferredStationAddress.mode==Mode::Unspecified);
  b.parent.addressResult=0;
  assert(b.cmdConnect("private",nullptr,pmk,nullptr,false,false,station)==0);
  assert(scheduled==before+1&&b._state==RTW88_STATE_AUTHENTICATING);
 }
 // Real menu passphrases (cipher 10, auth_upper 8) must work for WPA2-only
 // targets as well as transition APs. Beta 9 unconditionally forced SAE.
 const uint8_t psk[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
 const uint8_t transition[]={48,30,1,0,0,15,172,4,1,0,0,15,172,4,2,0,0,15,172,2,0,15,172,8,128,0,0,0,0,15,172,6};
 // A fresh exact target can stop a software scan, but AUTH stays deferred
 // until scan completion. Initial/unbound discovery still covers all bands.
 for(bool sae:{false,true}){
  RTW88IEEE80211 b;b._state=RTW88_STATE_SCANNING;b._manualScanChannelCount=39;
  RTW88BSS next=network("new",2);b._bssList=&next;next.observedMs=6500;next.last_seen_scan=7;
  memcpy(next.ies,transition,sizeof(transition));next.ies_len=sizeof(transition);
  ieee80211_channel channel;SupportedBand band{&channel,1};b.hw.wiphy_.bands[0]=&band;
  assert(!b.cachedJoinTargetReady("new",nullptr,sae));assert(!b.cachedJoinTargetReady("other",next.bssid,sae));
  assert(b.cachedJoinTargetReady("new",next.bssid,sae));
  simulatedNow=23000000000ULL;assert(!b.cachedJoinTargetReady("new",next.bssid,sae));simulatedNow=7000000000ULL;
  next.observedMs=7001;assert(!b.cachedJoinTargetReady("new",next.bssid,sae));next.observedMs=6500;
  next.last_seen_scan=5;assert(!b.cachedJoinTargetReady("new",next.bssid,sae));next.last_seen_scan=7;
  channel.flags=IEEE80211_CHAN_DISABLED;assert(!b.cachedJoinTargetReady("new",next.bssid,sae));
  channel.flags=IEEE80211_CHAN_RADAR;assert(!b.cachedJoinTargetReady("new",next.bssid,sae));
  next.beaconObservedMs=6500;assert(b.cachedJoinTargetReady("new",next.bssid,sae));channel.flags=0;
  if(sae){next.ies_len=0;assert(!b.cachedJoinTargetReady("new",next.bssid,true));next.ies_len=sizeof(transition);}
  uint8_t pmk[32]={};unsigned before=scheduled;
  assert(b.cmdConnect("new",sae?"password":nullptr,sae?nullptr:pmk,nullptr,false,sae)==0&&!b._manualScanAbort);
  assert(b.cmdConnect("new",sae?"password":nullptr,sae?nullptr:pmk,next.bssid,false,sae)==0);
  assert(b._manualScanAbort&&b._state==RTW88_STATE_SCANNING&&b._manualScanChannelCount==39&&scheduled==before);
  assert(b._deferredConnectPending);b._state=RTW88_STATE_IDLE;b._manualScanChannelCount=0;b.resumeDeferredJoin();
  assert(b._state==RTW88_STATE_AUTHENTICATING&&scheduled==before+1&&b._saeMode==sae);
 }
 RTW88AssocWire::Personal request={};request.lower=1;request.upper=8;request.cipher=10;
 request.ssidLength=3;memcpy(request.ssid,"iot",3);request.keyLength=8;memcpy(request.key,"password",8);
 for(bool oldSAE:{false,true})for(bool scanning:{false,true}){
  RTW88IEEE80211 b;b._targetBSS=network("old",1);b._saeMode=oldSAE;
  b._state=scanning?RTW88_STATE_SCANNING:RTW88_STATE_CONNECTED;b._associatedVisible=!scanning;b.parent.up=!scanning;
  RTW88BSS next=network("iot",2);memcpy(next.ies,psk,sizeof(psk));next.ies_len=sizeof(psk);next.akm=0xfac02;b._bssList=&next;
  AirPortRTW a{&b};assert(b.bssOffersPSKOnly("iot",nullptr));assert(a.handleMenuSAE(request)==0);
  if(scanning){assert(b._deferredConnectPending&&!b._deferredSAE);b._state=RTW88_STATE_IDLE;b.resumeDeferredJoin();}
  assert(b._state==RTW88_STATE_AUTHENTICATING&&!b._saeMode&&!b._pmkProvided&&!strcmp(b._password,"password"));
  queries(b,false,APPLE80211_S_AUTH);unsigned before=scheduled;
  assert(a.handleMenuSAE(request)==0&&scheduled==before); // duplicate live password joins coalesce
  auto changed=request;changed.key[0]='P';assert(a.handleMenuSAE(changed)==0&&scheduled==before+1&&!strcmp(b._password,"Password"));
  b._state=RTW88_STATE_ASSOCIATING;b._sta=&b.sta;auto s=response(b);b.processAssocResponse(&s);
  queries(b,false,APPLE80211_S_ASSOC);assert(!b.parent.up&&b._state==RTW88_STATE_HANDSHAKING);
  assert(b.cmdDisconnect()==0);
  // A transition target with the same password request must still use SAE.
  memcpy(next.ies,transition,sizeof(transition));next.ies_len=sizeof(transition);
  assert(!b.bssOffersPSKOnly("iot",nullptr));assert(a.handleMenuSAE(request)==0&&b._saeMode);
 }
 // Explicit SAE never falls back on a WPA2-only target, and an ambiguous
 // SSID containing a transition BSS never qualifies as PSK-only.
 {RTW88IEEE80211 b;RTW88BSS plain=network("iot",2),mixed=network("iot",3);
  memcpy(plain.ies,psk,sizeof(psk));plain.ies_len=sizeof(psk);b._bssList=&plain;AirPortRTW a{&b};
  request.upper=4096;assert(a.handleMenuSAE(request)==kIOReturnNotFound&&b._state==RTW88_STATE_IDLE);
  request.upper=8;memcpy(mixed.ies,transition,sizeof(transition));mixed.ies_len=sizeof(transition);plain.next=&mixed;
  assert(!b.bssOffersPSKOnly("iot",nullptr));assert(a.handleMenuSAE(request)==0&&b._saeMode&&b._targetBSS.bssid[5]==3);
  assert(b.bssOffersPSKOnly("iot",plain.bssid));assert(!b.bssOffersPSKOnly("missing",nullptr));
  auto shortKey=request;shortKey.keyLength=7;memcpy(shortKey.bssid,plain.bssid,6);
  assert(a.handleMenuSAE(shortKey)==kIOReturnBadArgument&&b._saeMode);
 }
 for(bool sae:{false,true}){
  RTW88IEEE80211 b;b._targetBSS=network("old",1);b._state=RTW88_STATE_CONNECTED;b._associatedVisible=true;b.parent.up=true;
  queries(b,true,APPLE80211_S_RUN);assert(b.cmdDisconnect()==0&&!b.parent.up);
  RTW88BSS next=network("new",2);b._bssList=&next;uint8_t pmk[32]={};
  const uint8_t transition[]={48,30,1,0,0,15,172,4,1,0,0,15,172,4,2,0,0,15,172,2,0,15,172,8,128,0,0,0,0,15,172,6};
  memcpy(next.ies,transition,sizeof(transition));next.ies_len=sizeof(transition);
  assert(b.cmdConnect("new",sae?"password":nullptr,sae?nullptr:pmk,next.bssid,false,sae)==0);
  assert(b._saeMode==sae);
  queries(b,false,APPLE80211_S_AUTH);assert(!b.parent.up);
  b._state=RTW88_STATE_ASSOCIATING;b._sta=&b.sta;auto s=response(b);b.processAssocResponse(&s);
  assert(s.freed&&b._state==RTW88_STATE_HANDSHAKING&&b.timer.armed);
  queries(b,false,APPLE80211_S_ASSOC);assert(!b.parent.up&&b.delegate.assoc==0);
  // Internal EAPOL does not need an Apple RUN latch. Its production M3/M4
  // completion is exercised by check_enterprise/check_wpa3_hardware.
  assert(b.cmdDisconnect()==0);queries(b,false,APPLE80211_S_INIT);
 }
 // A worker failure can retire a join before its queued down event is
 // delivered. Accepting the replacement must clear the old interface link.
 {RTW88IEEE80211 b;RTW88BSS n=network("new",2);b._bssList=&n;b.parent.up=true;b._connectCancelled=true;
  uint8_t pmk[32]={};assert(b.cmdConnect("new",nullptr,pmk,n.bssid,false)==0);
  assert(!b.parent.up);queries(b,false,APPLE80211_S_AUTH);}
 // Explicit cleanup in IDLE must also clear a pending old interface link.
 {RTW88IEEE80211 b;b.parent.up=true;assert(b.cmdDisconnect()==0&&!b.parent.up);}
 // Raw association remains visible for Apple RSN's EAPOL socket; open links
 // become usable immediately. Successful connected scans preserve RUN.
 for(bool external:{false,true}){
  RTW88IEEE80211 b;b._targetBSS=network("external-or-open",3);b._wpa2=external;b._externalSupplicant=external;
  b._state=RTW88_STATE_ASSOCIATING;b._sta=&b.sta;auto s=response(b);b.processAssocResponse(&s);
  queries(b,true,APPLE80211_S_RUN);assert(b.parent.up&&b.delegate.assoc==unsigned(external));
  b._state=RTW88_STATE_SCANNING;b._scanReturnState=RTW88_STATE_CONNECTED;queries(b,true,APPLE80211_S_RUN);
 }
 // Rejected association must notify failure through failJoin instead of
 // silently entering IDLE with no completion for the native join request.
 {RTW88IEEE80211 b;b._state=RTW88_STATE_ASSOCIATING;b._targetBSS=network("reject",4);
  auto s=response(b,17);b.processAssocResponse(&s);assert(b.failures==1);queries(b,false,APPLE80211_S_INIT);}
 puts("PASS: native WPA2 passphrase after WPA2/SAE or scan, production deferred continuation, duplicate/password routing, transition and explicit SAE downgrade fences, AUTH/ASSOC visibility, link cleanup, open/Apple RSN and scan RUN");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.cpp').write_text(pre + records + declarations + methods + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-I' + str(root / 'src/kext'),
                    str(p / 'test.cpp'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
