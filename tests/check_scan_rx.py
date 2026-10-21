#!/usr/bin/env python3
"""Production scan ingress/timeout/home restore and RX dispatcher regressions.

RF, firmware and packet-parser internals are mocked; this is not an over-air
interoperability test. Extracted methods always come from this checkout.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
controller = (root / 'src/kext/AirPortRTW.cpp').read_text()
backend = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
compat = (root / 'src/compat/rtw88_compat.c').read_text()

def method(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

multi = controller[controller.index('    case APPLE80211_IOC_SCAN_REQ_MULTIPLE:',
                                  controller.index('SInt32 AirPortRTW::handleNativeRequest(')):]
multi = multi[:multi.index('\n    case ', 1)]
# Run the real multi-scan switch arm too, not just a substring assertion.
multi = 'IOReturn AirPortRTW::scanMultiple(bool isSet) { switch (1) {\n' + multi.replace(
    'case APPLE80211_IOC_SCAN_REQ_MULTIPLE:', 'case 1:') + '\n} return 99; }\n'
scan = method(controller, 'IOReturn AirPortRTW::handleSCAN_REQ(')
timer = method(backend, 'void RTW88IEEE80211::onTimer()')
rx = method(backend, 'void RTW88IEEE80211::rxFrame(')
restore = method(compat, 'void rtw88_restore_connected_hw(')
pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
using IOReturn=int;using UInt32=uint32_t;using __le16=uint16_t;
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnUnsupported=2};
enum {RTW88_STATE_IDLE,RTW88_STATE_SCANNING,RTW88_STATE_AUTHENTICATING,
 RTW88_STATE_ASSOCIATING,RTW88_STATE_HANDSHAKING,RTW88_STATE_CONNECTED};
constexpr unsigned APPLE80211_VERSION=1,APPLE80211_MAX_SSID_LEN=32,
 APPLE80211_MAX_CHANNELS=64,APPLE80211_M_SCAN_DONE=42;
void IOLog(const char*,...){}void kprintf(const char*,...){}
int authRetries=0;void thread_call_enter(void*){++authRetries;}
struct RTW88StateResult{int state=RTW88_STATE_IDLE;};
struct apple80211_scan_data{unsigned version=1,ssid_len=0,num_channels=0;};
struct ScanBackend{
 int state=RTW88_STATE_IDLE,ret=0;unsigned scans=0;
 int cmdGetState(RTW88StateResult *p){p->state=state;return 0;}
 int cmdScan(){++scans;return ret;}
};
struct Netif{unsigned completions=0;
 void postMessage(int msg,void *data,size_t n){
  assert(msg==APPLE80211_M_SCAN_DONE&&n==sizeof(UInt32)&&*(UInt32*)data==0);
  ++completions;
 }
};
struct AirPortRTW{
 ScanBackend backend;ScanBackend *_ieee80211=&backend;
 Netif netif;Netif *_netif=&netif;
 bool _scanInProgress=false;unsigned _scanCursor=9;
 IOReturn handleSCAN_REQ(void*);IOReturn scanMultiple(bool);
};
struct Hw;struct Ops{void(*cancel_hw_scan)(Hw*,void*);};struct Hw{Ops *ops;};
constexpr unsigned RX_FLAG_FAILED_FCS_CRC=1,RX_FLAG_NO_SIGNAL_VAL=2;
struct ieee80211_rx_status{unsigned flag=0;int signal=-42;};
struct ieee80211_hdr{__le16 frame_control;};
struct sk_buff{
 unsigned len=24;alignas(8) uint8_t storage[64]={};uint8_t *data=storage;
 ieee80211_rx_status status;bool freed=false;
};
unsigned frees=0,signals=0,management=0,dataFrames=0,awdlFrames=0;
bool awdlConsumes=false;
void kfree_skb(sk_buff *s){assert(s&&!s->freed);s->freed=true;++frees;}
ieee80211_rx_status *IEEE80211_SKB_RXCB(sk_buff *s){return &s->status;}
bool rtw88StationSignal(const uint8_t*,unsigned,const uint8_t*,const uint8_t*,int,bool invalid){
 ++signals;return !invalid;
}
bool ieee80211_is_mgmt(__le16 fc){return (fc&12)==0;}
bool ieee80211_is_data(__le16 fc){return (fc&12)==8;}
struct RTW88IEEE80211{
 int _state=RTW88_STATE_IDLE,_rssi=-80;
 bool _enterprise=false,_enterpriseAuthorized=false,_manualScanAbort=false,canceled=false;
 unsigned _manualScanChannelCount=0,_rxFrameCount=0,completions=0,disconnects=0,failures=0;
 uint8_t _macAddr[6]={};struct{uint8_t bssid[6]={};}_targetBSS;
 Hw *_hw=nullptr;void *_vif=nullptr,*_connectTC=nullptr;
 bool authenticationCancelled(){return canceled;}
 void scanDone(bool aborted){
  if(_state!=RTW88_STATE_SCANNING)return;
  assert(aborted);++completions;_state=RTW88_STATE_IDLE;
 }
 void failJoin(const char*){++failures;_state=RTW88_STATE_IDLE;}
 void doDisconnect(){++disconnects;_state=RTW88_STATE_IDLE;}
 void onTimer();void rxFrame(sk_buff*);
 void processRxMgmt(sk_buff *s){++management;kfree_skb(s);}
 bool tryDeliverAWDLDataFrame(sk_buff *s){
  ++awdlFrames;if(awdlConsumes)kfree_skb(s);return awdlConsumes;
 }
 void processRxData(sk_buff *s){++dataFrames;kfree_skb(s);}
};
RTW88IEEE80211 *active=nullptr;
void syncCancel(Hw*,void*){active->scanDone(true);}
constexpr unsigned ETH_ALEN=6,PORT_SET_BSSID=1,RTW_FLAG_SCANNING=0;
struct rtw_dev{
 bool mutex=false,need_rfk=true;unsigned long flags[1]={1};struct{int fix_rate=0;}dm_info;
};
struct rtw_vif{uint8_t bssid[6]={};};
struct ieee80211_hw{rtw_dev *priv;};struct ieee80211_vif{rtw_vif *drv_priv;};
unsigned switches=0,calibrations=0,bssidWrites=0;
void mutex_lock(bool *m){assert(!*m);*m=true;}
void mutex_unlock(bool *m){assert(*m);*m=false;}
bool test_bit(unsigned bit,unsigned long *flags){return (*flags&(1UL<<bit))!=0;}
void rtw_set_channel(rtw_dev *d){
 assert(d->mutex);++switches;if(!test_bit(RTW_FLAG_SCANNING,d->flags))d->need_rfk=true;
}
void rtw_vif_port_config(rtw_dev *d,rtw_vif*,unsigned){assert(d->mutex);++bssidWrites;}
void rtw_chip_prepare_tx(rtw_dev *d){
 assert(d->mutex);if(d->need_rfk){++calibrations;d->need_rfk=false;}
}
'''
cases = r'''
int main(){
 apple80211_scan_data request;
 for(bool multiple:{false,true}){
  AirPortRTW c;
  auto call=[&]{return multiple?c.scanMultiple(true):c.handleSCAN_REQ(&request);};
  if(multiple)assert(c.scanMultiple(false)==kIOReturnUnsupported);
  else{
   assert(c.handleSCAN_REQ(nullptr)==kIOReturnBadArgument);
   request.version=2;assert(call()==kIOReturnBadArgument);request.version=1;
   request.ssid_len=33;assert(call()==kIOReturnBadArgument);request.ssid_len=0;
   request.num_channels=65;assert(call()==kIOReturnBadArgument);request.num_channels=0;
  }
  assert(call()==0&&c._scanInProgress&&c.backend.scans==1&&c._scanCursor==0);
  assert(call()==0&&c.backend.scans==1); // Coalesced, no second hardware scan.
  c._scanInProgress=false;c.backend.ret=19;
  assert(call()==19&&!c._scanInProgress&&c.backend.scans==2);
  c.backend.state=RTW88_STATE_CONNECTED;c._scanCursor=9;
  assert(call()==0&&!c._scanInProgress&&c.backend.scans==2);
  assert(c.netif.completions==1&&c._scanCursor==0);
 }
 RTW88IEEE80211 t;
 t._state=RTW88_STATE_SCANNING;t.onTimer();assert(t.completions==1);
 Ops ops{syncCancel};Hw hw{&ops};t._hw=&hw;active=&t;
 t._state=RTW88_STATE_SCANNING;t.onTimer();assert(t.completions==2);
 t._state=RTW88_STATE_SCANNING;t._manualScanChannelCount=4;t.onTimer();
 assert(t._manualScanAbort&&t.completions==2&&t._state==RTW88_STATE_SCANNING);
 t._state=RTW88_STATE_ASSOCIATING;t.onTimer();assert(t.failures==1);
 t._state=RTW88_STATE_AUTHENTICATING;t._connectTC=&t;t.onTimer();assert(authRetries==1);
 t.canceled=true;t.onTimer();assert(authRetries==1);
 t._state=RTW88_STATE_HANDSHAKING;t.onTimer();assert(t.disconnects==1);
 t._state=RTW88_STATE_CONNECTED;t.onTimer();assert(t.disconnects==1);
 t._enterprise=true;t.onTimer();assert(t.disconnects==2);
 t._state=RTW88_STATE_CONNECTED;t._enterpriseAuthorized=true;t.onTimer();assert(t.disconnects==2);
 rtw_dev dev;rtw_vif vif;ieee80211_hw radio{&dev};ieee80211_vif station{&vif};
 uint8_t bssid[6]={2,4,6,8,10,12};
 for(unsigned i=0;i<128;++i)rtw88_restore_connected_hw(&radio,&station,bssid);
 assert(switches==128&&!calibrations&&bssidWrites==128&&dev.need_rfk&&!dev.mutex);
 assert(std::memcmp(vif.bssid,bssid,6)==0&&dev.dm_info.fix_rate==255);
 dev.flags[0]=0;rtw88_restore_connected_hw(&radio,&station,bssid);
 assert(calibrations==1&&!dev.need_rfk);
 rtw88_restore_connected_hw(nullptr,&station,bssid);
 rtw88_restore_connected_hw(&radio,nullptr,bssid);
 rtw88_restore_connected_hw(&radio,&station,nullptr);assert(switches==129);
 RTW88IEEE80211 receiver;receiver.rxFrame(nullptr);assert(!frees);
 for(unsigned length=0;length<24;++length){sk_buff s;s.len=length;receiver.rxFrame(&s);assert(s.freed);}
 assert(frees==24&&!signals&&!receiver._rxFrameCount);
 // Every frame-control low byte with bad FCS is rejected before STA/AWDL.
 for(unsigned fc=0;fc<256;++fc){sk_buff s;s.data[0]=fc;s.status.flag=RX_FLAG_FAILED_FCS_CRC;
  receiver.rxFrame(&s);assert(s.freed);}
 assert(frees==280&&!signals&&!management&&!dataFrames&&!awdlFrames);
 for(unsigned fc:{0x80U,0x08U,0x04U}){
  sk_buff s;s.data[0]=fc;receiver.rxFrame(&s);assert(s.freed);
 }
 assert(frees==283&&signals==3&&management==1&&dataFrames==1&&awdlFrames==1);
 assert(receiver._rssi==-42&&receiver._rxFrameCount==3);
 awdlConsumes=true;sk_buff awdl;awdl.data[0]=8;awdl.status.signal=-10;
 awdl.status.flag=RX_FLAG_NO_SIGNAL_VAL;receiver.rxFrame(&awdl);
 assert(awdl.freed&&dataFrames==1&&awdlFrames==2&&receiver._rssi==-42&&frees==284);
 std::puts("PASS: production single/multiple scan ingress, coalescing, timeout/EAP guards, deferred calibration and RX FCS/ownership");
}
'''
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    (path / 'test.cpp').write_text('#include <initializer_list>\n' + pre +
                                  scan + multi + timer + rx + restore + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-g', str(path / 'test.cpp'), '-o', str(path / 'test')],
                   check=True, timeout=60)
    subprocess.run([str(path / 'test')], check=True, timeout=30,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
