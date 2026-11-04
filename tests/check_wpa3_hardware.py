#!/usr/bin/env python3
"""Production CAM install/M4 ordering + actual Session/HW RX replay boundary.
The chip itself is simulated with the tested software CCMP implementation.
"""
import os,shlex,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
source=(root/'src/kext/RTW88IEEE80211.cpp').read_text()
def method(sig):
 start=source.index(sig);p=source.index('{',start);depth=1;end=p+1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]+'\n'
methods=''.join(method(s) for s in ['bool RTW88IEEE80211::installKey(', 'bool RTW88IEEE80211::saeHardwareCCMP()', 'bool RTW88IEEE80211::wpa3InstallPairwise()', 'void RTW88IEEE80211::wpa3Eapol(', 'bool RTW88IEEE80211::wpa3RxData('])
pre=r'''
#include "RTW88WPA3.hpp"
#include <cassert>
#include <cstdlib>
#include <vector>
#include <cstdio>
using namespace RTW88WPA3;
#define RX_FLAG_DECRYPTED 1
#include "../compat/rtw88_rx_security.h"
using IOReturn=int;using s8=int8_t;using u_int=unsigned;
constexpr unsigned WLAN_CIPHER_SUITE_CCMP=0xfac04,WLAN_CIPHER_SUITE_TKIP=0xfac02,IEEE80211_KEY_FLAG_PAIRWISE=8;
constexpr unsigned SET_KEY=1,DISABLE_KEY=2,RTW88_STATE_SCANNING=1,RTW88_STATE_HANDSHAKING=4,RTW88_STATE_CONNECTED=5,kMillisecondScale=1,kRTW88EventHandshakeDone=1,kIONetworkLinkActive=1,kIONetworkLinkValid=2;
struct ieee80211_key_conf{uint32_t cipher=0;unsigned flags=0;uint8_t hw_key_idx=0,keylen=0,iv_len=0,icv_len=0;int8_t keyidx=0;uint8_t key[32]={};};
struct Status{unsigned flag=0;};struct sk_buff{uint8_t*data;unsigned len;Status status;};
Status*IEEE80211_SKB_RXCB(sk_buff*s){return &s->status;}
int mockSetKey(void*,int,void*,void*,ieee80211_key_conf*);
struct Ops{unsigned sets=0,disables=0;bool fail=false;int(*set_key)(void*,int,void*,void*,ieee80211_key_conf*)=mockSetKey;};
struct Hw{Ops ops_;Ops*ops=&ops_;};
int mockSetKey(void*h,int cmd,void*,void*,ieee80211_key_conf*k){auto&o=static_cast<Hw*>(h)->ops_;
 if(cmd==DISABLE_KEY){++o.disables;return 0;}++o.sets;if(o.fail)return -1;assert(k->keylen==16);k->hw_key_idx=4;return 0;}
void*IOMallocZero(size_t n){return calloc(1,n);}void IOFree(void*p,size_t){free(p);}
void IOLog(const char*,...){}const char*rtw88CipherName(unsigned){return "CCMP";}
void read_random(void*,unsigned){assert(false);}void clock_interval_to_deadline(unsigned,unsigned,uint64_t*d){*d=1;}
struct Timer{void cancelTimeout(){}void wakeAtTime(uint64_t){}};
struct Parent{unsigned ups=0;void setLinkStatus(unsigned s){if(s&kIONetworkLinkActive)++ups;}};struct Delegate{void rtw88Event(unsigned,void*){}};
struct Packet{std::vector<uint8_t>data;};using mbuf_t=Packet*;
mbuf_t rtw88_make_packet_mbuf(const uint8_t*p,unsigned n){return new Packet{{p,p+n}};}
struct RTW88IEEE80211{
 Session _sae;bool _saeMode=true,_saeSoftwareCCMP=false,failed=false;
 bool _m3KeysInstalled=false,_externalPTKInstalled=false,_externalGTKInstalled=false,_associatedVisible=false;
 bool _eapolTxProtect=false,_internalEapolTx=false;
 unsigned _saeHwTx=0,_saeHwRx=0,_saeSwRx=0,_saeRxRejected=0,_state=0,_scanReturnState=0,aggregations=0,m4=0,scanAborts=0;
 bool _manualScanAbort=false;
 uint8_t _macAddr[6]={},_ccmpTxPn[6]={};struct{uint8_t bssid[6]={};} _targetBSS;
 Hw hw;Hw*_hw=&hw;void*_vif=this,*_sta=this;
 ieee80211_key_conf *_ptkConf=nullptr,*_gtkConf=nullptr;
 Parent parent;Parent*_parent=&parent;Timer timer;Timer*_timer=&timer;Delegate*_delegate=nullptr;
 bool authenticationCancelled(){return false;}void failJoin(const char*){failed=true;_sae.authorized=false;}
 void roamTrace(const char*,unsigned=0){}
 bool abortActiveScan(bool wait){assert(!wait);++scanAborts;_manualScanAbort=true;return true;}
 void startTxAggregation(){++aggregations;}
 bool txDataFrame(mbuf_t p){if(p->data.size()==113&&p->data[19]==3&&p->data[20]==8){
  assert(_saeSoftwareCCMP||saeHardwareCCMP());if(!m4)assert(!_associatedVisible&&!parent.ups);++m4;}delete p;return true;}
 bool installKey(ieee80211_key_conf**,bool,uint8_t,uint32_t,const uint8_t*,uint8_t);
 bool saeHardwareCCMP()const;bool wpa3InstallPairwise();void wpa3Eapol(const uint8_t*,uint32_t);bool wpa3RxData(sk_buff*);
 void dispose(){free(_ptkConf);free(_gtkConf);_sae.crypto=nullptr;_sae.clear();}
};
void hardwareCases(const Session&,const std::vector<uint8_t>&);
'''
# Run the existing real SAE/AP exchange, intercepting each valid M3 fixture.
fixture=(root/'tests/wpa3_session_test.cpp').read_text().replace('#include "../src/kext/RTW88WPA3.hpp"','')
fixture=fixture.replace('m3[81]^=1;assert(', 'hardwareCases(s,m3);\n    m3[81]^=1;assert(',1)
cases=r'''
void hardwareCases(const Session&prepared,const std::vector<uint8_t>&m3){
 for(unsigned mode=0;mode<3;++mode){
  RTW88IEEE80211 b;b._sae=prepared;b._saeSoftwareCCMP=mode==1;b.hw.ops_.fail=mode==2;b._state=RTW88_STATE_HANDSHAKING;
  memcpy(b._targetBSS.bssid,prepared.peer,6);b.wpa3Eapol(m3.data(),m3.size());
  if(mode==2){assert(b.failed&&!b._sae.authorized&&!b.m4&&!b._ptkConf&&!b._associatedVisible&&!b.parent.ups);b.dispose();continue;}
  assert(b._sae.authorized&&b._m3KeysInstalled&&b.m4==1&&b.aggregations==1);
  assert(b._associatedVisible&&b._state==RTW88_STATE_CONNECTED&&b.parent.ups==1);
  assert(b.saeHardwareCCMP()==(mode==0)&&b.hw.ops_.sets==(mode==0?1u:0u));
  b._sae.txpn=77;b._sae.rx[4][0]=66;b.wpa3Eapol(m3.data(),m3.size());
  assert(b.m4==2&&b._sae.txpn==77&&b._sae.rx[4][0]==66&&b.hw.ops_.sets==(mode==0?1u:0u));
  if(mode==1){b.dispose();continue;}
  // TX hardware only inserts IV; chip adds MIC. Decrypt independently in SW.
  std::vector<uint8_t> tx(26+8+32);tx[0]=0x88;tx[1]=1;
  memcpy(tx.data()+4,b._sae.peer,6);memcpy(tx.data()+10,b._sae.own,6);
  assert(b._sae.prepareTx(tx.data(),tx.size())&&b._sae.txpn==78);
  tx.resize(tx.size()+8);assert(ccmp(tx.data(),tx.size(),b._sae.tk,78,true));assert(ccmp(tx.data(),tx.size(),b._sae.tk,78,false));
  // Incoming frame: simulate successful chip decryption + descriptor proof.
  std::vector<uint8_t> f(26+16+32);f[0]=0x88;f[1]=0x42;
  memcpy(f.data()+4,b._sae.own,6);memcpy(f.data()+10,b._sae.peer,6);f[26]=67;f[29]=0x20;
  for(unsigned i=34;i<66;++i)f[i]=uint8_t(i);
  assert(ccmp(f.data(),f.size(),b._sae.tk,67,true));auto cipher=f;
  assert(ccmp(f.data(),f.size(),b._sae.tk,67,false));auto plain=f;
  sk_buff skb{f.data(),unsigned(f.size()),{RX_FLAG_DECRYPTED}};
  // Bare DECRYPTED or ICV/CRC error cannot advance the replay window.
  assert(!b.wpa3RxData(&skb)&&b._sae.rx[4][0]==66);
  for(unsigned enc=0;enc<8;++enc)for(unsigned crc=0;crc<2;++crc)for(unsigned icv=0;icv<2;++icv)for(unsigned dec=0;dec<2;++dec){
   unsigned flag=dec?RX_FLAG_DECRYPTED:0;rtw88_rx_security_status(&flag,crc,icv,dec,enc);
   assert(bool(flag&RX_FLAG_RTW_CCMP_VERIFIED)==(!crc&&!icv&&dec&&enc==4));
   assert(bool(flag&RX_FLAG_RTW_INTEGRITY_FAILED)==bool(crc||icv));
  }
  skb.status.flag=RX_FLAG_DECRYPTED;rtw88_rx_security_status(&skb.status.flag,0,1,1,4);
  assert(!b.wpa3RxData(&skb)&&b._sae.rx[4][0]==66);
  skb.status.flag=RX_FLAG_DECRYPTED;rtw88_rx_security_status(&skb.status.flag,0,0,1,4);
  assert(b.wpa3RxData(&skb)&&b._saeHwRx==1&&b._sae.rx[4][0]==67);
  assert(!b.wpa3RxData(&skb)); // replay rejected after hardware MIC success
  // Management replay space is distinct; still authenticated and normalized.
  auto pmf=std::vector<uint8_t>(42);pmf[0]=0xc0;pmf[1]=0x40;
  memcpy(pmf.data()+4,b._sae.own,6);memcpy(pmf.data()+10,b._sae.peer,6);memcpy(pmf.data()+16,b._sae.peer,6);
  pmf[24]=1;pmf[27]=0x20;pmf[32]=3;assert(ccmp(pmf.data(),pmf.size(),b._sae.tk,1,true));
  assert(ccmp(pmf.data(),pmf.size(),b._sae.tk,1,false));size_t n=pmf.size();bool proof=false;
  assert(b._sae.management(pmf.data(),n,proof,true)&&proof&&n==26&&pmf[24]==3);
  // Software receive still works if a chip leaves unicast encrypted.
  b._sae.rx[4][0]=66;f=cipher;skb.data=f.data();skb.status.flag=0;
  assert(b.wpa3RxData(&skb)&&b._saeSwRx==1&&f==plain);
  b.dispose();
 }
 puts("PASS: real M3/CAM/M4 ordering, install failure, SW override, duplicate M3 PN retention, HW descriptor integrity and replay boundary");
}
'''
# Include the same SAE archive sources as the host suite, without running it twice.
host=(root/'experimental/wpa3/test_host.py').read_text();env={'__file__':str(root/'experimental/wpa3/test_host.py')}
# Compile private crypto archive with the suite's established source list/flags.
exec(compile(host[:host.index('with tempfile.TemporaryDirectory(')],str(root/'experimental/wpa3/test_host.py'),'exec'),env)
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp);(p/'test.cpp').write_text(pre+methods+fixture+cases)
 cc=shlex.split(os.environ.get('CC','cc'));cxx=shlex.split(os.environ.get('CXX','c++'))
 san=['-fsanitize=address,undefined','-fno-omit-frame-pointer'];objs=[]
 for i,src in enumerate(env['sources']):
  obj=p/f'{i}.o';subprocess.run([*cc,*env['flags'],*san,'-c',str(src),'-o',str(obj)],check=True);objs.append(str(obj))
 obj=p/'ccmp.o';subprocess.run([*cxx,'-std=c++17','-O2',*san,'-c',str(root/'src/kext/RTW88WPA3Crypto.cpp'),'-o',str(obj)],check=True);objs.append(str(obj))
 # Fixture also includes the test header by relative path; provide its directory.
 subprocess.run([*cxx,'-std=c++17',*san,'-g','-I'+str(root/'src/kext'),'-I'+str(root/'tests'),str(p/'test.cpp'),*objs,'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=60,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
