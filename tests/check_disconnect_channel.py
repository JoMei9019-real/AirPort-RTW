#!/usr/bin/env python3
"""Exercise the real host-disconnect/restore/DEAUTH path with RF callbacks.

The callback observes the tuned channel and intact PMF state at submission.
No radio, Apple framework or elapsed-time performance is simulated.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()

def method(signature):
    start = source.index(signature)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

methods = ''.join(method(signature) for signature in (
    'IOReturn RTW88IEEE80211::cmdDisconnect()',
    'void RTW88IEEE80211::doDisconnect()',
    'void RTW88IEEE80211::restoreSTAChannelAfterAWDL()',
    'bool RTW88IEEE80211::txMgmtFrame('))

pre = r'''
#include "RTW88WPA3.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <initializer_list>
using IOReturn=int;using RTW88State=int;
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_SCANNING=1,RTW88_STATE_CONNECTED=5;
constexpr int kIOReturnSuccess=0,kIOReturnBusy=1,kIONetworkLinkValid=1,kRTW88EventDisconnected=2;
constexpr int NL80211_NUM_BANDS=2,BSS_CHANGED_ASSOC=1,IEEE80211_FTYPE_MGMT=0,IEEE80211_STYPE_DEAUTH=0xc0,WLAN_REASON_DEAUTH_LEAVING=3;
constexpr int GFP_ATOMIC=0,IEEE80211_TX_CTL_FIRST_FRAGMENT=1,IEEE80211_TX_CTL_NO_ACK=2,IEEE80211_TX_CTL_REQ_TX_STATUS=4;
uint16_t cpu_to_le16(uint16_t x){return x;}
void IOLog(const char*,...){}
struct ieee80211_hdr_3addr{uint16_t frame_control,duration;uint8_t addr1[6],addr2[6],addr3[6];uint16_t seq;};
static_assert(sizeof(ieee80211_hdr_3addr)==24);
struct ieee80211_channel{unsigned hw_value;int band=0;};
struct ieee80211_supported_band{ieee80211_channel*channels;int n_channels,band;};
struct Wiphy{ieee80211_supported_band*bands[2]{};};
struct ieee80211_bss_conf{bool assoc=true;unsigned aid=7;};
struct Vif{ieee80211_bss_conf bss_conf;struct{bool assoc=true;unsigned aid=7;}cfg;};
struct ieee80211_tx_info{unsigned flags=0;struct{Vif*vif=nullptr;}control;};
struct sk_buff{uint8_t data[256];unsigned len=0;ieee80211_tx_info info;};
struct ieee80211_tx_control{void*sta;};
struct Hw;struct RTW88IEEE80211;
void radioTx(Hw*,ieee80211_tx_control*,sk_buff*);
void bssChanged(Hw*,Vif*,ieee80211_bss_conf*,int);
struct Ops{void(*tx)(Hw*,ieee80211_tx_control*,sk_buff*)=radioTx;void(*bss_info_changed)(Hw*,Vif*,ieee80211_bss_conf*,int)=bssChanged;};
struct Hw{Ops*ops;Wiphy*wiphy;struct{struct{ieee80211_channel*chan;}chandef;}conf;};
sk_buff*alloc_skb(unsigned,int){return new sk_buff;}
void skb_reserve(sk_buff*,unsigned){}
void skb_put_data(sk_buff*s,const uint8_t*p,unsigned n){assert(n<=sizeof(s->data));memcpy(s->data,p,n);s->len=n;}
ieee80211_tx_info*IEEE80211_SKB_CB(sk_buff*s){return &s->info;}
struct Parent{unsigned downs=0;void setLinkStatus(int);};
struct Delegate{unsigned events=0;void rtw88Event(int,void*);};
struct Timer{void cancelTimeout(){}};
struct RTW88IEEE80211{
 bool _powered=true,_associatedVisible=true,_awdlOffChannel=true,_disconnectVoluntary=false;
 bool _roamScanWorkerPending=false,_manualScanAbort=false,_saeMode=false,keys=true,worker=false,abortOK=true;
 unsigned _manualScanChannelCount=0,_awdlPreparedChannel=6,_deauthReason=0,_assocAID=7;
 unsigned restores=0,nulls=0,txs=0,protectedTxs=0,clears=0,releases=0,firmwareClears=0;
 int _state=5,_scanReturnState=0;
 char _password[64]="password";uint8_t _macAddr[6]={2,0,0,0,0,1};
 struct{unsigned channel=116;uint8_t bssid[6]={2,0,0,0,0,2};}_targetBSS;
 struct{bool authorized=false;}_sae;
 ieee80211_channel channels[2]={{6},{116}};
 ieee80211_supported_band band{channels,2,1};Wiphy wiphy;Ops ops;Hw hw{&ops,&wiphy,{{&channels[0]}}};Hw*_hw=&hw;
 Vif vif;Vif*_vif=&vif;Parent parent;Parent*_parent=&parent;Delegate delegate;Delegate*_delegate=&delegate;
 Timer timer;Timer*_timer=&timer;std::vector<std::string>stages;
 RTW88IEEE80211(){wiphy.bands[1]=&band;}
 void roamTrace(const char*s,unsigned=0){stages.emplace_back(s);}
 void cancelRoamSwitch(){}void clearDeferredJoin(){}
 void cancelAuthentication(){worker=false;}
 bool abortActiveScan(bool){if(abortOK){_state=5;_manualScanChannelCount=0;_roamScanWorkerPending=false;}return abortOK;}
 void setConnectedChandef(ieee80211_channel*c){assert(_associatedVisible&&keys);hw.conf.chandef.chan=c;++restores;}
 bool txNullFunc(bool asleep){assert(!asleep&&hw.conf.chandef.chan->hw_value==116&&_associatedVisible&&keys);++nulls;return true;}
 bool wpa3TxMgmt(const uint8_t*f,unsigned n){assert(_saeMode&&_sae.authorized&&keys);assert(hw.conf.chandef.chan->hw_value==116);assert(f[0]==0xc0&&n==26);++protectedTxs;return true;}
 void clearKeys(){assert(!worker);if(_state!=0)assert(txs+protectedTxs==1);keys=false;_sae.authorized=false;_saeMode=false;++clears;}
 void clearAssocRsnIE(){}
 void releaseSta(){assert(!keys&&!worker);if(_state!=0)assert(firmwareClears==1);++releases;}
 IOReturn cmdDisconnect();void doDisconnect();void restoreSTAChannelAfterAWDL();bool txMgmtFrame(const uint8_t*,uint32_t);
};
RTW88IEEE80211*active;
void rtw88_restore_connected_hw_timeslice(Hw*,Vif*,const uint8_t*){assert(active->_associatedVisible&&active->keys);}
void radioTx(Hw*h,ieee80211_tx_control*,sk_buff*s){
 assert(h->conf.chandef.chan->hw_value==116);assert(active->keys);
 assert(s->len==26&&s->data[0]==0xc0&&s->data[24]==3&&s->info.control.vif==active->_vif);
 assert(s->info.flags&IEEE80211_TX_CTL_REQ_TX_STATUS);++active->txs;delete s;
}
void bssChanged(Hw*,Vif*v,ieee80211_bss_conf*b,int){
 assert(!b->assoc&&!b->aid&&!v->cfg.assoc&&!v->cfg.aid&&!active->_assocAID&&!active->keys);
 ++active->firmwareClears;
}
void Parent::setLinkStatus(int){assert(active->_state==0&&!active->_associatedVisible&&!active->keys&&active->releases==1);++downs;}
void Delegate::rtw88Event(int,void*){assert(active->_state==0&&!active->_associatedVisible&&active->parent.downs==1);++events;}
'''

cases = r'''
int main(){
 // Both ordinary and PMF-protected DEAUTH must leave on the old AP channel.
 for(bool sae:{false,true})for(bool offChannel:{false,true}){
  RTW88IEEE80211 b;active=&b;b._saeMode=sae;b._sae.authorized=sae;b._awdlOffChannel=offChannel;
  if(!offChannel)b.hw.conf.chandef.chan=&b.channels[1];
  assert(b.cmdDisconnect()==0);
  assert(b.restores==unsigned(offChannel)&&b.nulls==unsigned(offChannel));
  assert(b.protectedTxs==unsigned(sae)&&b.txs==unsigned(!sae));
  assert(!b._awdlOffChannel&&!b._associatedVisible&&!b.keys&&b._state==0);
  assert(b._disconnectVoluntary&&b._deauthReason==8&&b.clears==1&&b.releases==1);
  assert(b.parent.downs==1&&b.delegate.events==1&&b.stages.back()=="host-disconnect-complete");
 }
 // An unsuccessful scan drain retains its station and its radio ownership.
 {RTW88IEEE80211 b;active=&b;b._state=1;b._scanReturnState=5;b._manualScanChannelCount=39;b.abortOK=false;
  assert(b.cmdDisconnect()==kIOReturnBusy&&b.keys&&!b.restores&&!b.clears&&!b.releases);
  assert(b.stages.back()=="disconnect-scan-drain-busy");}
 // A connected scan must relinquish ownership before the same teardown.
 {RTW88IEEE80211 b;active=&b;b._state=1;b._scanReturnState=5;b._manualScanChannelCount=39;
  assert(b.cmdDisconnect()==0&&b.restores==1&&b.txs==1&&!b._manualScanChannelCount);}
 // Disconnected discovery retains the scan transaction and sends no DEAUTH.
 {RTW88IEEE80211 b;active=&b;b._state=1;b._associatedVisible=false;b._scanReturnState=0;
  assert(b.cmdDisconnect()==0&&b.keys&&!b.clears&&!b.restores&&!b.txs);
  assert(b.stages.back()=="disconnect-scan-only-ack");}
 puts("PASS: real disconnect restores AP channel before RUN clears, preserves PMF keys through DEAUTH submission, orders teardown/link events and retains scan ownership on abort failure");
}
'''

with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.cpp').write_text(pre + methods + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(root / 'src/kext'), str(p / 'test.cpp'),
                    '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
