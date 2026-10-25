#!/usr/bin/env python3
"""Production k/v/r wire helpers and runtime methods with host TX/PM mocks.
No over-air interoperability, actual roam, PMF, or FT crypto is claimed.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
controller = (root / 'src/kext/AirPortRTW.cpp').read_text()
header = (root / 'src/kext/RTW88IEEE80211.hpp').read_text()

def method(signature):
    start = source.index(signature)
    pos = source.index('{', start)
    depth, end = 1, pos + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

methods = ''.join(method(s) for s in (
    'void RTW88IEEE80211::resetRoamingState()',
    'bool RTW88IEEE80211::roamingActionsReady() const',
    'bool RTW88IEEE80211::sendRoamingAction(',
    'void RTW88IEEE80211::roamingTick(',
    'void RTW88IEEE80211::handleRoamingAction('))
assert 'resetRoamingState();' in method('void RTW88IEEE80211::clearKeys()')
assert 'handleRoamingAction(skb->data, skb->len' in method('void RTW88IEEE80211::processRxMgmt(')
assert '_roamingAssistEnabled = false' in header
assert 'roaming && roaming->isTrue()' in controller
assert 'setProperty("ROAM_R_FT_ENABLED", kOSBooleanFalse)' in controller
assoc = method('bool RTW88IEEE80211::buildAssocReq(')
assert 'if (requestRrm || _rm.advertised) cap |= 0x1000' in assoc
assert '(_rm.advertised?0x70:0)' in assoc
assert 'roamCaps.neighborReport && !roamCaps.pmfRequired' in assoc
assert 'WLAN_EID_MOBILITY_DOMAIN' not in assoc and 'WLAN_EID_FAST_BSS_TRANSITION' not in assoc
diag = controller[controller.index('void AirPortRTW::diagnosticsTimerFired('):
                  controller.index('void AirPortRTW::waitForDiagnosticsIdle()')]
assert diag.index('!__atomic_load_n(&self->_pmTransition') < diag.index('->roamingTick(')
assert diag.index('->roamingTick(') < diag.index('__atomic_store_n(&self->_diagnosticsInHardware, false')
pre = r'''
#include "RTW88Roaming.hpp"
#include "RTW88RRM.hpp"
#include <cassert>
#include <cstdio>
#include <vector>
template<class... T> void IOLog(const char *, T...) {}
using namespace RTW88Roaming;
constexpr int RTW88_STATE_CONNECTED=5,RTW88_STATE_SCANNING=1;
constexpr uint32_t WLAN_CIPHER_SUITE_CCMP=0x000fac04;
struct Parent {bool allowed=true,btmAvailable=false;unsigned scheduled=0;
 bool roamingActionsAllowed(){return allowed;}bool btmControlAvailable(){return btmAvailable&&allowed;}
 bool scheduleBtmControl(unsigned delay){assert(delay>0&&delay<=100);++scheduled;return btmControlAvailable();}};
struct RTW88IEEE80211 {
 RTW88RRM::State _rm;
 void rrmReceive(const uint8_t*,uint32_t,uint64_t){}
 void rrmTick(uint64_t){}
 void rrmCancel(const char*){_rm.phase=0;}
 bool _autoRoamEnabled=false,_autoScanPending=false,_stationNeighborReport=false;uint64_t _autoNextMs=0;
 uint32_t _autoScanGeneration=0,_autoScans=0,_autoSwitches=0;const char *_autoStage="disabled";
 ParseDiagnostic _neighborDiagnostic;const char *_neighborReject="none";
 bool _stationBTM=false;unsigned _btmPhase=0;BtmRequest _btmRequest;
 uint8_t _btmSource[6]={},_btmTarget[6]={};
 uint64_t _btmDeadline=0,_btmAckDeadline=0,_btmReplyIdentity=0,_btmAckIdentity=0;
 uint32_t _btmScanGeneration=0,_btmLastStatus=255,_btmLastResponseToken=0;bool _btmScanned=false;const char *_btmStage="idle";
 void cancelBTM(const char*){_btmPhase=0;}
 void queueBtm(const BtmRequest&,uint64_t){}
 uint32_t _neighborActionLength=0,_neighborActualToken=0;uint64_t _neighborResponseAge=0;
 Session _roaming;uint32_t _roamingStats[Count]={};
 bool _roamScanActive=false,_roamScanWorkerPending=false;uint32_t _roamScanResult=0,_roamLastResponseCount=0,_roamTestID=0;
 unsigned _roamLogLevel=1;uint64_t _roamRefreshLast=0;
 bool roamScanActive()const{return _roamScanActive;}
 void roamTrace(const char*,uint32_t=0){}
 bool _roamingAssistEnabled=false,_roamingCapsValid=false;
 bool _powered=true,_associatedVisible=true,_awdlOffChannel=false;
 bool _wpa2=true,_enterprise=false,_externalSupplicant=false,canceled=false;
 int _state=RTW88_STATE_CONNECTED;
 Parent parent;Parent *_parent=&parent;
 void *_ptkConf=this,*_gtkConf=this;
 uint8_t _macAddr[6]={2,1,2,3,4,5};uint16_t _txSeq=0;
 struct {
  uint8_t bssid[6]={2,6,7,8,9,10};char ssid[33]="Test";uint8_t ssid_len=4,channel=6;uint16_t beacon_interval=100;
  uint32_t cipher=WLAN_CIPHER_SUITE_CCMP;uint8_t ies[512]={};uint16_t ies_len=0;
 } _targetBSS;
 bool txSucceeds=true;std::vector<std::vector<uint8_t>> submitted;
 bool authenticationCancelled()const{return canceled;}
 void roamSwitchTick(uint64_t){}
 bool txMgmtFrame(const uint8_t*p,uint32_t n){
  if(!txSucceeds)return false;submitted.emplace_back(p,p+n);return true;
 }
 void resetRoamingState();bool roamingActionsReady()const;
 bool sendRoamingAction(const uint8_t*,uint32_t);
 void roamingTick(uint64_t);void handleRoamingAction(const uint8_t*,uint32_t,uint64_t);
};
'''
cases = r'''
std::vector<uint8_t> apIEs(){return {
 70,5,2,0,0,0,0, 127,3,0,0,8, 54,3,0x34,0x12,3,
 48,24,1,0,0,15,172,4,1,0,0,15,172,4,2,0,0,15,172,2,0,15,172,4,0,0};}
std::vector<uint8_t> neighbor(unsigned id=1){return {
 52,16,2,9,8,7,6,uint8_t(id),0x11,0x22,0x33,0x44,81,6,7,3,1,255};}
std::vector<uint8_t> frame(RTW88IEEE80211 &b,std::vector<uint8_t> body){
 std::vector<uint8_t> f(24);f[0]=0xd0;
 memcpy(f.data()+4,b._macAddr,6);memcpy(f.data()+10,b._targetBSS.bssid,6);
 memcpy(f.data()+16,b._targetBSS.bssid,6);f.insert(f.end(),body.begin(),body.end());return f;
}
void setAP(RTW88IEEE80211 &b){auto ie=apIEs();
 memcpy(b._targetBSS.ies,ie.data(),ie.size());b._targetBSS.ies_len=ie.size();}
void deliver(RTW88IEEE80211 &b,std::vector<uint8_t> body,uint64_t now){
 auto f=frame(b,body);b.handleRoamingAction(f.data(),f.size(),now);
}
int main(){
 Capabilities caps;auto ie=apIEs();
 assert(capabilities(ie.data(),ie.size(),caps));
 assert(caps.neighborReport&&caps.btm&&caps.mobilityDomain&&caps.mdid==0x1234&&caps.ftPolicy==3&&caps.ftAkms==2);
 auto bad=ie;bad[1]=6;assert(!capabilities(bad.data(),bad.size(),caps)&&!caps.mobilityDomain);
 bad=ie;bad.insert(bad.end(),{54,3,1,2,0});assert(!capabilities(bad.data(),bad.size(),caps));
 bad=ie;bad.back()=0;bad[bad.size()-2]=0x40;
 assert(capabilities(bad.data(),bad.size(),caps)&&caps.pmfRequired);
 auto nr=neighbor();Candidates list;
 ParseDiagnostic diagnostic;
 auto zeroClass=nr;zeroClass[12]=0;
 assert(!candidateIEs(zeroClass.data(),zeroClass.size(),list,&diagnostic));
 assert(diagnostic.code==ParseOperatingClass&&diagnostic.offset==12);
 auto zeroChannel=nr;zeroChannel[13]=0;
 assert(!candidateIEs(zeroChannel.data(),zeroChannel.size(),list,&diagnostic));
 assert(diagnostic.code==ParseChannel&&diagnostic.offset==13);
 auto shortSub=nr;shortSub[16]=3;
 assert(!candidateIEs(shortSub.data(),shortSub.size(),list,&diagnostic)&&diagnostic.code==ParseSubLength);
 assert(candidateIEs(nr.data(),nr.size(),list)&&list.count==1);
 assert(list.entries[0].info==0x44332211&&list.entries[0].channel==6&&list.entries[0].preference==255);
 for(size_t n=1;n<nr.size();++n)assert(!candidateIEs(nr.data(),n,list)&&list.count==0);
 auto duplicate=nr;duplicate.insert(duplicate.end(),nr.begin(),nr.end());
 assert(candidateIEs(duplicate.data(),duplicate.size(),list)&&list.count==1);
 std::vector<uint8_t> many;
 for(unsigned i=1;i<=20;++i){auto entry=neighbor(i);many.insert(many.end(),entry.begin(),entry.end());}
 assert(candidateIEs(many.data(),many.size(),list)&&list.count==16&&list.truncated);
 bad=nr;bad[2]=1;assert(!candidateIEs(bad.data(),bad.size(),list));
 bad=nr;bad[16]=2;assert(!candidateIEs(bad.data(),bad.size(),list));
 BtmRequest request;
 std::vector<uint8_t> btm={10,7,99,1,0x34,0x12,10};btm.insert(btm.end(),nr.begin(),nr.end());
 assert(btmRequest(btm.data(),btm.size(),request)&&request.candidates.count==1&&request.disassociationTimer==0x1234);
 std::vector<uint8_t> optional={10,7,0,24,0,0,1,4,10,0,0,0,0,0,0,0,0,0,0,3,'u','r','l'};
 assert(btmRequest(optional.data(),optional.size(),request));
 for(size_t n=0;n<optional.size();++n)assert(!btmRequest(optional.data(),n,request));
 optional[8]=9;assert(!btmRequest(optional.data(),optional.size(),request));
 uint8_t out[40]={};assert(neighborRequest(out,40,1,(const uint8_t*)"Test",4)==9);
 assert(out[0]==5&&out[1]==4&&out[2]==1&&out[3]==0&&out[4]==4);
 assert(!neighborRequest(out,8,1,(const uint8_t*)"Test",4));
 assert(!neighborRequest(out,40,0,(const uint8_t*)"Test",4));
 assert(btmReject(out,40,0)==5&&out[3]==1&&out[2]==0);
 assert(!btmReject(out,4,1));
 // Exercise real runtime paths: default-off still reports passive AP metadata.
 RTW88IEEE80211 b;setAP(b);b.roamingTick(1000);
 assert(b.submitted.empty()&&b._roamingStats[APMdid]==0x1234);
 b._roamingAssistEnabled=true;b.roamingTick(1001);
 assert(b.submitted.size()==1&&b._roaming.pending&&b._roamingStats[RequestTx]==1);
 auto sent=b.submitted.back();assert(sent.size()==33&&sent[24]==5&&sent[25]==4);
 assert(!memcmp(sent.data()+4,b._targetBSS.bssid,6)&&!memcmp(sent.data()+10,b._macAddr,6));
 uint8_t token=b._roaming.pendingToken;
 b.roamingTick(1100);assert(b.submitted.size()==1);
 std::vector<uint8_t> response={5,5,token};response.insert(response.end(),nr.begin(),nr.end());
 auto f=frame(b,response);
 for(unsigned offset:{0U,4U,10U,16U,22U}){
  auto forged=f;forged[offset]^=1;b.handleRoamingAction(forged.data(),forged.size(),1200);
 }
 auto protectedFrame=f;protectedFrame[1]|=0x40;
 b.handleRoamingAction(protectedFrame.data(),protectedFrame.size(),1200);
 assert(b._roaming.pending&&!b._roamingStats[ResponseRx]);
 auto wrong=response;wrong[2]++;deliver(b,wrong,1200);assert(b._roamingStats[ResponseInvalid]==1);
 auto malformed=response;malformed.pop_back();deliver(b,malformed,1200);
 assert(b._roaming.pending&&b._roamingStats[ResponseInvalid]==2);
 assert(b._neighborDiagnostic.code==ParseIELength&&b._neighborDiagnostic.offset==3);
 assert(!strcmp(b._neighborReject,"ie-length")&&b._neighborActualToken==token);
 deliver(b,response,1200);assert(!b._roaming.pending&&b._roamingStats[ResponseRx]==1&&b._roamingStats[NeighborCount]==1);
 deliver(b,response,1201);assert(b._roamingStats[ResponseInvalid]==3);
 b.roamingTick(31200);assert(!b._roaming.neighbors.count&&!b._roamingStats[NeighborCount]);
 deliver(b,btm,32000);assert(b._roamingStats[BtmRx]==1&&b._roamingStats[BtmRejectTx]==1);
 sent=b.submitted.back();assert(sent.size()==29&&sent[24]==10&&sent[25]==8&&sent[26]==99&&sent[27]==1);
 deliver(b,btm,32001);assert(b._roamingStats[BtmRateLimited]==1&&b.submitted.size()==2);
 b.txSucceeds=false;deliver(b,btm,33000);assert(b._roamingStats[BtmTxFail]==1);
 assert(b._state==RTW88_STATE_CONNECTED&&b._associatedVisible&&b._ptkConf&&b._gtkConf);
 // PM, security, scan and channel ownership fences all suppress TX/processing.
 const auto before=b._roamingStats[BtmRx];
 for(unsigned guard=0;guard<9;++guard){
  switch(guard){case 0:b._powered=false;break;case 1:b.parent.allowed=false;break;
   case 2:b._enterprise=true;break;case 3:b._externalSupplicant=true;break;
   case 4:b._awdlOffChannel=true;break;case 5:b._state=RTW88_STATE_SCANNING;break;
   case 6:b.canceled=true;break;case 7:b._gtkConf=nullptr;break;case 8:b._roaming.ap.pmfRequired=true;break;}
  deliver(b,btm,40000);assert(b._roamingStats[BtmRx]==before);
  b._powered=true;b.parent.allowed=true;b._enterprise=false;b._externalSupplicant=false;
  b._awdlOffChannel=false;b._state=RTW88_STATE_CONNECTED;b.canceled=false;b._gtkConf=&b;b._roaming.ap.pmfRequired=false;
 }
 b.resetRoamingState();assert(!b._roaming.pending&&!b._roamingStats[APMdid]&&!b._roamingCapsValid);
 assert(b._roaming.tokenCounter==token);
 b.txSucceeds=true;b.roamingTick(50000);assert(b._roaming.pendingToken!=token);
 auto stale=response;deliver(b,stale,50001);assert(b._roaming.pending);
 b.roamingTick(55000);assert(!b._roaming.pending&&b._roamingStats[ResponseTimeout]==1);
 const auto attempts=b._roamingStats[RequestTx];b.roamingTick(70000);assert(b._roamingStats[RequestTx]==attempts);
 b.resetRoamingState();b.txSucceeds=false;b.roamingTick(80000);assert(!b._roaming.pending&&b._roamingStats[RequestTxFail]==1);
 b.roamingTick(140000);assert(b._roamingStats[RequestTxFail]==2);
 b.roamingTick(145000);assert(b._roamingStats[RequestTxFail]==2); // no rapid retry on failed TX
 // Corrupt/untrusted data: exercise all wire parsers under ASan/UBSan.
 uint32_t seed=7;uint8_t fuzz[1025];
 for(unsigned trial=0;trial<30000;++trial){
  size_t n=trial%sizeof(fuzz);for(size_t i=0;i<n;++i){seed=1664525*seed+1013904223;fuzz[i]=uint8_t(seed>>24);}
  capabilities(fuzz,n,caps);candidateIEs(fuzz,n,list);btmRequest(fuzz,n,request);
  ParseDiagnostic diag;neighborResponse(fuzz,n,1,list,&diag);
  assert(diag.offset<=MaxActionBytes+3);actionFromAP(fuzz,n,b._macAddr,b._targetBSS.bssid);
 }
 std::puts("PASS: production k/v/r parser fuzz, bounded cache, FT metadata, source/token/PM fences, reject-only BTM, timeouts and lifecycle");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.cpp').write_text(pre + methods + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-g', '-I' + str(root / 'src/kext'), str(p / 'test.cpp'),
                    '-o', str(p / 'test')], check=True, timeout=60)
    subprocess.run([str(p / 'test')], check=True, timeout=60,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
