#!/usr/bin/env python3
"""Exercise production ADDBA retries/response identity, with mocked radio TX."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/kext/RTW88IEEE80211.cpp').read_text()
def method(sig):
 start=s.index(sig);pos=s.index('{',start);end=pos+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]+'\n'
methods=''.join(method(x) for x in ['void RTW88IEEE80211::sendAddbaRequest(', 'void RTW88IEEE80211::startTxAggregation()', 'void RTW88IEEE80211::maintainTxAggregation(', 'void RTW88IEEE80211::handleBackAction('])
pre=r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>
constexpr unsigned RTW88_STATE_CONNECTED=5,IEEE80211_FTYPE_MGMT=0,IEEE80211_STYPE_ACTION=0xd0,WLAN_CATEGORY_BACK=3,WLAN_ACTION_ADDBA_REQ=0,WLAN_ACTION_ADDBA_RESP=1,WLAN_ACTION_DELBA=2;
uint16_t cpu_to_le16(uint16_t n){return n;}
void IOLog(const char*,...){}
struct ieee80211_hdr_3addr{uint16_t frame_control,duration_id;uint8_t addr1[6],addr2[6],addr3[6];uint16_t seq_ctrl;};
struct Sta{struct{struct{bool ht_supported=true;}ht_cap;}deflink;};
struct RTW88IEEE80211{
 bool _powered=true,_associatedVisible=true,_txBaActive=false,_txBaPending=false,_saeMode=true,offchannel=false,scan=false,transmit=true;
 unsigned _state=5,_txBaAttempts=0,_txBaLastStatus=0xffff;uint64_t _txBaRetryMs=0;
 struct{bool authorized=true,pending=false;}_sae;
 uint8_t _baDialog=0,_baTid=0,_macAddr[6]={2,1,2,3,4,5};uint16_t _txSeq=0,_dataSeq=0,_baBufSize=64;
 struct{uint8_t bssid[6]={2,9,8,7,6,5};}_targetBSS;
 Sta sta;Sta*_sta=&sta;void*_hw=this;
 static constexpr unsigned kRxBaNumTid=8;
 std::vector<std::vector<uint8_t>>frames;
 bool htAllowed()const{return true;}bool staTxBlockedByAWDL()const{return offchannel;}bool staTxBlockedByScan()const{return scan;}
 bool txMgmtFrame(const uint8_t*p,unsigned n){assert(_txBaPending);frames.emplace_back(p,p+n);return transmit;}
 void rxBaSetup(unsigned,unsigned,unsigned){}void rxBaTeardown(unsigned){}
 void sendAddbaResponse(uint8_t,uint8_t,uint16_t,uint16_t,uint16_t=0){}
 void sendAddbaRequest(uint8_t);void startTxAggregation();void maintainTxAggregation(uint64_t);void handleBackAction(const uint8_t*,uint32_t);
};
'''
cases=r'''
int main(){
 RTW88IEEE80211 b;b.startTxAggregation();assert(b._txBaPending&&b.frames.size()==1&&b._txBaAttempts==1);
 b.maintainTxAggregation(100);b.maintainTxAggregation(2099);assert(b.frames.size()==1);
 b.offchannel=true;b.maintainTxAggregation(2100);assert(b.frames.size()==1);
 b.offchannel=false;b._sae.pending=true;b.maintainTxAggregation(2100);assert(b.frames.size()==1);
 b._sae.pending=false;b.maintainTxAggregation(4100);assert(b.frames.size()==2&&b._txBaPending);
 auto dialog=b._baDialog;uint8_t reply[]={3,1,uint8_t(dialog-1),0,0,2,0,0,0};
 b.handleBackAction(reply,9);assert(!b._txBaActive&&b._txBaPending);
 reply[2]=dialog;reply[5]=6;b.handleBackAction(reply,9);assert(!b._txBaActive); // wrong TID
 reply[5]=2;b.handleBackAction(reply,9);assert(b._txBaActive&&!b._txBaPending&&b._txBaLastStatus==0);
 b.maintainTxAggregation(99999);assert(b.frames.size()==2);
 RTW88IEEE80211 timeout;timeout.startTxAggregation();timeout.maintainTxAggregation(100);
 timeout.maintainTxAggregation(2100);timeout.maintainTxAggregation(4100);timeout.maintainTxAggregation(99999);
 assert(timeout._txBaAttempts==3&&timeout.frames.size()==3);
 RTW88IEEE80211 stopped;stopped._powered=false;stopped.maintainTxAggregation(10);stopped.maintainTxAggregation(99999);assert(stopped.frames.empty());
 RTW88IEEE80211 failed;failed.transmit=false;failed.startTxAggregation();assert(!failed._txBaPending&&failed._txBaAttempts==1);
 puts("PASS: production ADDBA identity/TID, lost-response retry, three-attempt bound, pending SAE/offchannel/power gates and TX failure");
}
'''
with tempfile.TemporaryDirectory() as directory:
 p=Path(directory);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
