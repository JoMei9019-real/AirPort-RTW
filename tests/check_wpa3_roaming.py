#!/usr/bin/env python3
"""Real PMF crypto plus production neighbor/RRM/BTM methods, with RF/OS mocks."""
import os, shlex, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
fixture=(root/'tests/check_control_coordination.py').read_text()
ns={'__file__':str(root/'tests/check_control_coordination.py')}
exec(compile(fixture[:fixture.index("\ncases=r'''")],str(root/'tests/check_control_coordination.py'),'exec'),ns)
pre,method,methods=ns['pre'],ns['method'],ns['methods']
pre=pre.replace('struct {bool authorized=true,pending=false;} _sae;','RTW88WPA3::Session _sae;')
assert 'RTW88WPA3::Session _sae;' in pre
pre=pre.replace('void *IOMallocZero(size_t n){return calloc(1,n);}',r'''
void *IOMallocZero(size_t n){return calloc(1,n);}
void IOFree(void*p,size_t){free(p);}
struct sk_buff{uint8_t*data;uint32_t len;};
void skb_trim(sk_buff*s,size_t n){assert(n<=s->len);s->len=uint32_t(n);}
''')
pre=pre.replace('bool txMgmtFrame(const uint8_t*p,uint32_t n){',r'''
 bool wpa3TxMgmt(const uint8_t*,uint32_t);bool wpa3Mgmt(sk_buff*,bool&);
 bool txMgmtFrame(const uint8_t*p,uint32_t n){
  if(_saeMode&&_sae.authorized&&!(p[1]&0x40)&&RTW88WPA3::robustManagement(p,n))return wpa3TxMgmt(p,n);
''')
methods+=''.join(method(s) for s in ('bool RTW88IEEE80211::wpa3TxMgmt(', 'bool RTW88IEEE80211::wpa3Mgmt('))
assert 'RTW88WPA3::robustManagement(frame,len)' in method('bool RTW88IEEE80211::txMgmtFrame(')
rx=method('void RTW88IEEE80211::processRxMgmt(')
assert rx.index('wpa3Mgmt(skb,pmfVerified)')<rx.index('handleRoamingAction(skb->data, skb->len, ns / 1000000ULL,pmfVerified)')
cases=r'''
uint8_t ies[]={70,5,2,0,0,0,0,127,3,0,0,8,48,26,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,8,0xc0,0,0,0,0,15,172,6};
void init(RTW88IEEE80211&b,Hw&hw,RTW88BSS&candidate,uint64_t now){
 b._hw=&hw;b._bssList=&candidate;b._rssi=-65;b._saeMode=true;
 b._roamingAssistEnabled=b._roamingCapsValid=b._autoRoamEnabled=b._stationBTM=true;
 b.parent.btmAvailable=true;b._roaming.ap.neighborReport=b._roaming.ap.btm=true;
 b._sae.active=b._sae.confirmed=b._sae.authorized=true;
 memcpy(b._sae.own,b._macAddr,6);memcpy(b._sae.peer,b._targetBSS.bssid,6);
 for(unsigned i=0;i<16;++i)b._sae.tk[i]=uint8_t(i+1);
 strcpy(b._password,"SAE roaming password");
 memcpy(b._targetBSS.ies,ies,sizeof(ies));b._targetBSS.ies_len=sizeof(ies);
 memcpy(candidate.ies,ies,sizeof(ies));candidate.ies_len=sizeof(ies);candidate.observedMs=now;candidate.rssi=-40;
}
std::vector<uint8_t> plain(RTW88IEEE80211&b,const std::vector<uint8_t>&body){
 std::vector<uint8_t> f(24+body.size());f[0]=0xd0;
 memcpy(f.data()+4,b._macAddr,6);memcpy(f.data()+10,b._targetBSS.bssid,6);memcpy(f.data()+16,b._targetBSS.bssid,6);
 memcpy(f.data()+24,body.data(),body.size());return f;
}
std::vector<uint8_t> packet(RTW88IEEE80211&b,const std::vector<uint8_t>&body,uint64_t pn){
 auto p=plain(b,body);std::vector<uint8_t> f(p.size()+16);memcpy(f.data(),p.data(),24);f[1]=0x40;
 memcpy(f.data()+32,p.data()+24,body.size());uint8_t v[6];RTW88WPA3::putpn(v,pn);
 f[24]=v[0];f[25]=v[1];f[27]=0x20;memcpy(f.data()+28,v+2,4);
 assert(RTW88WPA3::ccmp(f.data(),f.size(),b._sae.tk,pn,true));return f;
}
bool receive(RTW88IEEE80211&b,std::vector<uint8_t> f,uint64_t now){
 sk_buff skb{f.data(),uint32_t(f.size())};bool verified=false;
 if(!b.wpa3Mgmt(&skb,verified))return false;
 b.handleRoamingAction(skb.data,skb.len,now,verified);return true;
}
std::vector<uint8_t> decoded(RTW88IEEE80211&b,std::vector<uint8_t> f,uint64_t pn){
 assert(f[1]&0x40);assert(RTW88WPA3::ccmp(f.data(),f.size(),b._sae.tk,pn,false));
 memmove(f.data()+24,f.data()+32,f.size()-40);f.resize(f.size()-16);f[1]&=~0x40;return f;
}
int main(){
 ieee80211_supported_band band;Wiphy w{{&band}};Ops ops;Hw hw{&w,&ops};RTW88BSS candidate;
 RTW88IEEE80211 b;init(b,hw,candidate,1000);
 b.roamingTick(1000);assert(b._roaming.pending&&b.submitted.size()==1);
 auto nr=decoded(b,b.submitted[0],1);assert(nr[24]==5&&nr[25]==4);
 std::vector<uint8_t> response={5,5,b._roaming.pendingToken,52,13};
 response.insert(response.end(),candidate.bssid,candidate.bssid+6);response.insert(response.end(),{0,0,0,0,81,6,7});
 auto unprotected=plain(b,response);assert(!receive(b,unprotected,1001)&&b._roaming.pending);
 b.handleRoamingAction(unprotected.data(),unprotected.size(),1001);assert(b._roaming.pending); // no PMF proof
 auto good=packet(b,response,1),bad=good;bad.back()^=1;
 assert(!receive(b,bad,1001)&&b._sae.rx[4][17]==0&&b._roaming.pending);
 assert(receive(b,good,1001)&&!b._roaming.pending&&b._roaming.neighbors.count==1);
 assert(!receive(b,good,1002)&&b._sae.rx[4][17]==1); // management replay
 auto forged=packet(b,response,2);forged[10]^=2;
 assert(!receive(b,forged,1002)&&b._sae.rx[4][17]==1);
 std::vector<uint8_t> request={10,7,11,1,0,0,255,52,16};
 request.insert(request.end(),candidate.bssid,candidate.bssid+6);
 request.insert(request.end(),{0,0,0,0,81,6,7,3,1,200});
 assert(!receive(b,plain(b,request),1003)&&!b._btmPhase);
 assert(receive(b,packet(b,request,2),1003)&&b._btmPhase==1);
 b.btmTick(1004);assert(b._btmPhase==2&&b.submitted.size()==2&&!b.joins);
 auto accept=b.submitted.back();assert(accept.size()==51&&b._btmProtectedReceipt.matches(accept.data(),accept.size()));
 auto payload=decoded(b,accept,2);assert(payload[24]==10&&payload[25]==8&&payload[27]==0);
 b.observeBtmTx(accept.data(),accept.size(),false);b.btmTick(1005);assert(!b.joins);
 bad=accept;bad[24]^=1;b.observeBtmTx(bad.data(),bad.size(),true);
 bad=accept;bad[22]^=0x10;b.observeBtmTx(bad.data(),bad.size(),true);
 bad=accept;bad[4]^=2;b.observeBtmTx(bad.data(),bad.size(),true);
 b.observeBtmTx(payload.data(),payload.size(),true);b.btmTick(1006);assert(!b.joins);
 b.observeBtmTx(accept.data(),accept.size(),true);b.btmTick(1007);
 assert(b.joins==1&&b._saeMode&&b._roamSwitch.sae&&b._roamSwitch.phase==1);
 assert(!strcmp(b._roamSwitch.password,"SAE roaming password"));
 // The Radio Measurement request and its reply must both traverse real PMF.
 RTW88IEEE80211 rm;init(rm,hw,candidate,2000);rm._rm.advertised=true;
 std::vector<uint8_t> measurement={5,0,7,0,0,38,16,19,0,5,115,36,0,0,100,0,2,255,255,255,255,255,255};
 assert(!receive(rm,plain(rm,measurement),2000)&&!rm._rm.received);
 assert(receive(rm,packet(rm,measurement,1),2000)&&rm._rm.received==1);
 rm.rrmTick(2001);assert(rm.submitted.size()==1);
 auto report=decoded(rm,rm.submitted[0],1);assert(report[24]==5&&report[25]==1&&report[26]==7);
 // SA Query replies still use PMF; a non-robust public/vendor action is not
 // interpreted as an authenticated roaming request, including before keys.
 RTW88IEEE80211 query;init(query,hw,candidate,3000);
 assert(!receive(query,packet(query,{8,0,0x12,0x34},1),3000)&&query.submitted.size()==1);
 auto reply=decoded(query,query.submitted[0],1);assert(reply[24]==8&&reply[25]==1&&reply[26]==0x12&&reply[27]==0x34);
 for(unsigned category:{4U,7U,11U,15U,20U,21U,22U,127U}){
  auto f=plain(query,{uint8_t(category),0});f[10]^=2;size_t n=f.size();bool verified=true;
  assert(!RTW88WPA3::robustManagement(f.data(),n));
  assert(query._sae.management(f.data(),n,verified)&&!verified);
 }
 // A pending acceptance is erased by PM/cancel; a late completion cannot
 // recreate a receipt or trigger another roam.
 RTW88IEEE80211 cancel;init(cancel,hw,candidate,4000);
 assert(receive(cancel,packet(cancel,request,1),4000));cancel.btmTick(4001);accept=cancel.submitted.back();
 cancel.parent.allowed=false;cancel.btmTick(4002);assert(!cancel._btmPhase&&!cancel._btmProtectedReceipt.matches(accept.data(),accept.size()));
 cancel.observeBtmTx(accept.data(),accept.size(),true);cancel.btmTick(4003);assert(!cancel.joins);
 puts("PASS: real PMF neighbor/RRM/BTM TX/RX, MIC/replay/source rejection, encrypted acceptance ACK identity/PN, SAE switch and PM cancellation");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p=Path(directory);(p/'test.cpp').write_text(pre+methods+cases)
    cc=shlex.split(os.environ.get('CC','cc'));cxx=shlex.split(os.environ.get('CXX','c++'))
    san=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run([*cc,'-O2',*san,'-c',str(root/'experimental/wpa3/rtw80211/sae/rtw_sae_crypto.c'),'-o',str(p/'crypto.o')],check=True)
    subprocess.run([*cxx,'-std=c++17','-O2',*san,'-c',str(root/'src/kext/RTW88WPA3Crypto.cpp'),'-o',str(p/'ccmp.o')],check=True)
    subprocess.run([*cxx,'-std=c++17',*san,'-g','-I'+str(root/'src/kext'),str(p/'test.cpp'),str(p/'crypto.o'),str(p/'ccmp.o'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
