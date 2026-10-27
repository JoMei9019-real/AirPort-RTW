#!/usr/bin/env python3
"""Production RSN policy, PMK lifecycle and controlled port under ASan/UBSan.
This is deliberately not a claim of an over-the-air EAP/Enterprise test.
"""
import os
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
source = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
def method(signature):
    start = source.index(signature)
    pos = source.index('{', start)
    depth, end = 1, pos + 1
    while depth:
        if source[end] == '{': depth += 1
        elif source[end] == '}': depth -= 1
        end += 1
    return source[start:end] + '\n'
header = (root / 'src/kext/RTW88IEEE80211.hpp').read_text()
ready = header[header.index('bool      externalKeysReady()'):header.index('    IOReturn  cmdInstallEnterprisePMK')]
methods = ''.join(method(s) for s in (
    'void RTW88IEEE80211::clearKeys()',
    'IOReturn RTW88IEEE80211::installEnterprisePMKGated(',
    'IOReturn RTW88IEEE80211::cmdInstallExternalKey(',
    'UInt32 RTW88IEEE80211::outputPacket(',
    'void RTW88IEEE80211::deliverEthernet(',
    'void RTW88IEEE80211::handleEAPOL('))
# Exercise production routing decisions as well as the reusable policy.
assert 'if (_pmkProvided) handleEAPOL(llc + 8' in source
assert 'memcpy(eapol + 99, _assocRsnIE, key_data_len)' in source
assert 'if (!_enterprise || ethertype != ETH_P_PAE)' in source
controller = (root / 'src/kext/AirPortRTW.cpp').read_text()
assert 'cmdConnect(ssid, nullptr, pmk, bssid, enterprise)' in controller
assert 'key->key_cipher_type == RTW88Enterprise::AppleMsk' in controller
assert 'RTW88Enterprise::auth(' in controller
pre = r'''
#include "RTW88Enterprise.hpp"
#include "RTW88WPA3.hpp"
#include "RTW88Lifecycle.hpp"
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <iostream>
using IOReturn=int; using UInt32=uint32_t;
constexpr int kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,kIOReturnUnsupported=3;
constexpr int kIOReturnOutputDropped=5,kIOReturnOutputSuccess=0,kIOReturnOutputStall=6;
constexpr int DISABLE_KEY=0,MBUF_WAITOK=0,ETH_P_PAE=0x888e;
constexpr unsigned kIONetworkLinkActive=1,kIONetworkLinkValid=2;
enum State { RTW88_STATE_IDLE, RTW88_STATE_CONNECTED,RTW88_STATE_SCANNING,RTW88_STATE_HANDSHAKING };
struct Packet { std::vector<uint8_t> bytes; }; using mbuf_t=Packet*;
void mbuf_freem(mbuf_t p){ delete p; }
size_t mbuf_pkthdr_len(mbuf_t p){return p->bytes.size();}
int mbuf_copydata(mbuf_t p,size_t o,size_t n,void* dst){
 if(o>p->bytes.size()||n>p->bytes.size()-o)return 1;
 memcpy(dst,p->bytes.data()+o,n);return 0;}
int mbuf_copyback(mbuf_t p,size_t o,size_t n,const void* src,int){
 if(o>p->bytes.size()||n>p->bytes.size()-o)return 1;
 memcpy(p->bytes.data()+o,src,n);return 0;}
struct Parent { int injected=0; mbuf_t allocateInputPacket(size_t n){return new Packet{std::vector<uint8_t>(n)};}
 void injectRxFrame(mbuf_t p){++injected;delete p;} void setLinkStatus(unsigned){} };
struct ieee80211_key_conf { uint8_t key[32]; uint8_t keyidx=0,keylen=0,hw_key_idx=0; };
constexpr uint32_t WLAN_CIPHER_SUITE_CCMP=0x000fac04,WLAN_CIPHER_SUITE_TKIP=0x000fac02;
constexpr int kMillisecondScale=1,kRTW88EventHandshakeDone=6;
struct Timer { void cancelTimeout(){} void wakeAtTime(uint64_t){} };
struct Delegate { int done=0;void rtw88Event(int,void*){++done;} };
void clock_interval_to_deadline(int,int,uint64_t *d){*d=1;}
void read_random(void*p,size_t n){memset(p,0x11,n);}
void derivePTK(const uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint8_t*p){memset(p,0xaa,64);}
bool micValid=false,allowGtk=true;
bool eapol_mic_ok(const uint8_t*,const uint8_t*,uint32_t){return micValid;}
bool aes_unwrap_128(const uint8_t*,const uint8_t*,uint16_t,uint8_t*out,uint16_t*n){memset(out,0,16);*n=16;return true;}
bool extract_gtk_from_kde(const uint8_t*,uint16_t,uint8_t*k,uint8_t*n,uint8_t*i){
 if(!allowGtk){*n=0;return false;}memset(k,0xbb,16);*n=16;*i=1;return true;}
void IOFree(void* p,size_t){free(p);}
template<class...T> void IOLog(const char*,T...){}
struct Ops { void (*set_key)(void*,int,void*,void*,ieee80211_key_conf*)=nullptr; };
struct Hw { Ops *ops=nullptr; };
struct RTW88IEEE80211 {
 RTW88Lifecycle::Wake _wakeTrace;RTW88Lifecycle::Queue _queueTrace;
 void wakeTrace(const char*){}
 void recordTxEvent(unsigned i){++_queueTrace.events[i];}
 bool staTxBlockedByScan()const{return _state==RTW88_STATE_SCANNING&&_scanReturnState==RTW88_STATE_CONNECTED&&_manualScanChannelCount&&!_manualScanOnHomeChannel;}
 uint32_t _roamDataRx=0;void roamTrace(const char*,uint32_t=0){}
 bool _saeMode=false;struct {bool authorized=false;} _sae;void clearWPA3(){}void wpa3Eapol(const uint8_t*,uint32_t){}
 bool _powered=true,_associatedVisible=true,_enterprise=true,_enterpriseAuthorized=false;
 bool _externalSupplicant=true,_wpa2=true,_externalPTKInstalled=false,_externalGTKInstalled=false;
 bool _pmkProvided=false,_internalEapolTx=false,_rxCcmpIvSkipLogged=false,_snonceValid=false;
 bool _m3KeysInstalled=false,_handshakePending=false,cancelled=false,_manualScanOnHomeChannel=false;
 bool m4Submit=true;Timer timer;Timer *_timer=&timer;Delegate delegate;Delegate *_delegate=&delegate;
 uint8_t _macAddr[6]={};
 State _state=RTW88_STATE_CONNECTED,_scanReturnState=RTW88_STATE_IDLE;
 int _manualScanChannelCount=0,tx=0;
 Hw *_hw=nullptr; void *_rtwdev=(void*)1,*_vif=(void*)1,*_sta=(void*)1;
 Parent *_parent=nullptr;
 ieee80211_key_conf *_ptkConf=nullptr,*_gtkConf=nullptr;
 uint8_t _pmk[32]={},_password[64]={},_ptk[64]={},_gtk[32]={},_ccmpTxPn[8]={};
 uint8_t _anonce[32]={},_snonce[32]={},_replayCtr[8]={},_installedM3ReplayCtr[8]={};
 struct {uint8_t bssid[6]={2,3,4,5,6,7};uint32_t group_cipher=0x000fac04;} _targetBSS;
 bool authenticationCancelled(){return cancelled;}
 __READY__
 bool installKey(ieee80211_key_conf **p,bool,uint8_t idx,uint32_t,const uint8_t*k,uint8_t n){
  if(!*p)*p=(ieee80211_key_conf*)calloc(1,sizeof(**p));
  assert(n<=32);memcpy((*p)->key,k,n);(*p)->keylen=n;(*p)->keyidx=idx;return true;}
 bool sendEAPOLKey(int step,const uint8_t*,bool,bool,bool){return step!=4 || m4Submit;}
 void handleEAPOL(const uint8_t*,uint32_t);
 void startTxAggregation(){}
 void resetRoamingState(){}
 bool txDataFrame(mbuf_t p){++tx;delete p;return true;}
 IOReturn installEnterprisePMKGated(const uint8_t*,uint32_t,const uint8_t*);
 IOReturn cmdInstallExternalKey(bool,uint8_t,uint32_t,const uint8_t*,uint8_t);
 UInt32 outputPacket(mbuf_t); void clearKeys();
 void deliverEthernet(const uint8_t*,const uint8_t*,uint16_t,const uint8_t*,uint32_t);
};
'''
tests = r'''
std::vector<uint8_t> rsn(uint8_t akm=1){return {48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,akm,0,0};}
mbuf_t packet(uint16_t type){auto p=new Packet{std::vector<uint8_t>(18)};p->bytes[12]=type>>8;p->bytes[13]=type;return p;}
int main(){
 using namespace RTW88Enterprise;
 auto e=rsn(),p=rsn(2);
 assert(selectedDot1x(e.data(),e.size())); assert(!selectedDot1x(p.data(),p.size()));
 assert(auth(1,4,0,e.data(),e.size())==Auth::Enterprise);
 assert(auth(1,32,0,e.data(),e.size())==Auth::Enterprise);
 assert(auth(1,4,32,e.data(),e.size())==Auth::Invalid);
 assert(auth(1,8,32,p.data(),p.size())==Auth::Personal);
 assert(auth(1,12,32,p.data(),p.size())==Auth::Personal);
 assert(auth(1,8,0,p.data(),p.size())==Auth::Invalid);
 assert(auth(1,0,0,nullptr,0)==Auth::Open);
 assert(auth(1,0,32,nullptr,0)==Auth::Invalid);
 assert(auth(1,4|256,0,e.data(),e.size())==Auth::Invalid);
 assert(auth(1,32|8,32,e.data(),e.size())==Auth::Invalid);
 assert(auth(1,512,0,e.data(),e.size())==Auth::Invalid);
 for(size_t n=0;n<e.size();++n)assert(!selectedDot1x(e.data(),n));
 auto bad=e;bad[20]=0x40;assert(!selectedDot1x(bad.data(),bad.size()));
 bad=e;bad[20]=0x80;assert(!selectedDot1x(bad.data(),bad.size()));
 bad=e;bad[7]=2;assert(!selectedDot1x(bad.data(),bad.size()));
 bad=e;bad[8]=255;bad[9]=255;assert(!selectedDot1x(bad.data(),bad.size()));
 bad=e;bad[14]=0;assert(!selectedDot1x(bad.data(),bad.size()));
 for(uint8_t akm:{uint8_t(3),uint8_t(5),uint8_t(8),uint8_t(12)}){bad=rsn(akm);assert(!selectedDot1x(bad.data(),bad.size()));}
 // Deterministic malformed RSN input under sanitizers, exact allocation sizes.
 uint32_t rand=0x1248a;
 for(unsigned i=0;i<40000;i++){
  rand=rand*1664525+1013904223;std::vector<uint8_t> v(rand%258);
  for(auto&x:v){rand=rand*1664525+1013904223;x=rand>>24;}
  Rsn r;parse(v.data(),v.size(),r);selectedDot1x(v.data(),v.size());
 }
 uint8_t type=255,identity[]={2,0,0,5,1,4,0,5,1};
 assert(eapol(identity,sizeof(identity),type)&&type==0);
 assert(!eapol(identity,3,type));assert(!eapol(identity,8,type));
 uint8_t keyFrame[]={2,3,0,0};assert(eapol(keyFrame,4,type)&&type==3);
 RTW88IEEE80211 b;Hw hw;b._hw=&hw;Parent parent;b._parent=&parent;
 // Off-channel connected scans retain the exact mbuf for a later retry.
 b._state=RTW88_STATE_SCANNING;b._scanReturnState=RTW88_STATE_CONNECTED;b._manualScanChannelCount=3;
 auto deferred=packet(0x888e);
 assert(b.outputPacket(deferred)==kIOReturnOutputStall&&deferred->bytes.size()==18&&b.tx==0);
 assert(b._queueTrace.events[RTW88Lifecycle::StallScan]==1);
 b._manualScanOnHomeChannel=true;assert(b.outputPacket(deferred)==0&&b.tx==1);
 b.tx=0;b._state=RTW88_STATE_CONNECTED;b._scanReturnState=RTW88_STATE_IDLE;b._manualScanChannelCount=0;
 uint8_t pmk[32];memset(pmk,0x91,32);uint8_t zero[6]={},wrong[6]={1,1,1,1,1,1};
 assert(b.installEnterprisePMKGated(pmk,31,zero)==kIOReturnBadArgument);
 assert(b.installEnterprisePMKGated(pmk,32,wrong)==kIOReturnBadArgument);
 b._associatedVisible=false;assert(b.installEnterprisePMKGated(pmk,32,zero)==kIOReturnNotReady);b._associatedVisible=true;
 assert(b.installEnterprisePMKGated(pmk,32,b._targetBSS.bssid)==0);
 assert(b._pmkProvided&&!b.externalKeysReady());
 assert(b.installEnterprisePMKGated(pmk,32,zero)==0);
 pmk[0]^=1;assert(b.installEnterprisePMKGated(pmk,32,zero)==kIOReturnNotReady);pmk[0]^=1;
 assert(!memcmp(b._pmk,pmk,32));
 // A PMK is not authorization; ordinary IPv4/IPv6/ARP cannot cross either way.
 for(uint16_t et:{uint16_t(0x800),uint16_t(0x86dd),uint16_t(0x806)}){
  assert(b.outputPacket(packet(et))==kIOReturnOutputDropped);
  b.deliverEthernet(zero,zero,et,identity,sizeof(identity));
 }
 assert(b.tx==0&&parent.injected==0);
 assert(b.outputPacket(packet(0x888e))==0);
 b.deliverEthernet(zero,zero,0x888e,identity,sizeof(identity));assert(parent.injected==1);
 assert(b.cmdInstallExternalKey(true,0,Ccmp,pmk,16)==kIOReturnNotReady);
 // Production four-way handler with crypto mocked: protocol/authorization
 // sequencing only, not a cryptographic interoperability test.
 std::vector<uint8_t> m1(99);m1[0]=2;m1[1]=3;m1[3]=95;m1[4]=2;m1[6]=0x8a;m1[16]=1;
 memset(m1.data()+17,0x42,32);
 b.handleEAPOL(m1.data(),m1.size());assert(b._state==RTW88_STATE_HANDSHAKING&&!b.externalKeysReady());
 std::vector<uint8_t> m3(115);m3[0]=2;m3[1]=3;m3[3]=111;m3[4]=2;m3[5]=0x13;m3[6]=0xca;m3[16]=2;
 memset(m3.data()+17,0x42,32);m3[98]=16;
 b.handleEAPOL(m3.data(),m3.size());assert(!b.externalKeysReady()); // invalid MIC
 micValid=true;allowGtk=false;
 b.handleEAPOL(m3.data(),m3.size());assert(!b.externalKeysReady()); // GTK absent
 allowGtk=true;b.m4Submit=false;
 b.handleEAPOL(m3.data(),m3.size());assert(!b.externalKeysReady()); // M4 not submitted
 assert(parent.injected==1&&b.delegate.done==0);
 b.m4Submit=true;b.handleEAPOL(m3.data(),m3.size());
 assert(b.externalKeysReady()&&b._state==RTW88_STATE_CONNECTED&&b.delegate.done==1);
 assert(b.outputPacket(packet(0x800))==0);
 b.deliverEthernet(zero,zero,0x800,identity,sizeof(identity));assert(parent.injected==2);
 memset(b._password,0x5a,sizeof(b._password));b.clearKeys();
 for(auto x:b._pmk)assert(x==0);
 for(auto x:b._password)assert(x==0);
 assert(!b._enterprise&&!b._enterpriseAuthorized&&!b._pmkProvided&&!b._ptkConf&&!b._gtkConf);
 assert(b.installEnterprisePMKGated(pmk,32,zero)==kIOReturnNotReady);
 // Existing Personal/open data behavior and external callback order preserved.
 b._externalSupplicant=false;assert(b.outputPacket(packet(0x800))==0);
 b._externalSupplicant=true;
 assert(b.cmdInstallExternalKey(false,1,Ccmp,pmk,16)==0);assert(!b.externalKeysReady());
 assert(b.cmdInstallExternalKey(true,0,Ccmp,pmk,16)==0);assert(b.externalKeysReady());
 b.clearKeys();
 std::cout<<"PASS: RSN/auth fixtures+fuzz, EAPOL bounds, bound PMK lifecycle, actual TX/RX port gates, M3/M4 authorization sequencing and cleanup\n";
}
'''
with tempfile.TemporaryDirectory() as td:
    p=Path(td);(p/'test.cpp').write_text(pre.replace('__READY__',ready)+methods+tests)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-g','-O1','-fno-omit-frame-pointer','-fsanitize=address,undefined','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=0"})
