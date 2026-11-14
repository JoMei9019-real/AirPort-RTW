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
rx_wrapper = (root / 'src/compat/rtw88_rx.c').read_text()

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
noise_query = method(controller, 'case APPLE80211_IOC_NOISE:')
noise_query = ('IOReturn AirPortRTW::getNoise(bool isSet, void *data) { switch (1) {\n' +
               noise_query.replace('case APPLE80211_IOC_NOISE:', 'case 1:') + '} return 99; }\n')
scan = method(controller, 'IOReturn AirPortRTW::handleSCAN_REQ(')
timer = method(backend, 'void RTW88IEEE80211::onTimer()')
rx = method(backend, 'void RTW88IEEE80211::rxFrame(')
noise = method(backend, 'RTW88LinkNoise::Reading RTW88IEEE80211::linkNoise()')
descriptor = method(rx_wrapper, 'void rtw_rx_query_rx_desc(').replace(
    '_Static_assert(', 'static_assert(').replace('*d = desc;', '*d = static_cast<const rtw_rx_desc *>(desc);')
restore = method(compat, 'void rtw88_restore_connected_hw(')
pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "RTW88LinkNoise.hpp"
using IOReturn=int;using UInt32=uint32_t;using __le16=uint16_t;using __le32=uint32_t;
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnUnsupported=2};
enum {RTW88_STATE_IDLE,RTW88_STATE_SCANNING,RTW88_STATE_AUTHENTICATING,
 RTW88_STATE_ASSOCIATING,RTW88_STATE_HANDSHAKING,RTW88_STATE_CONNECTED};
constexpr unsigned APPLE80211_VERSION=1,APPLE80211_MAX_SSID_LEN=32,
 APPLE80211_MAX_CHANNELS=64,APPLE80211_M_SCAN_DONE=42,APPLE80211_UNIT_DBM=1;
void IOLog(const char*,...){}void kprintf(const char*,...){}
int authRetries=0;void thread_call_enter(void*){++authRetries;}
struct RTW88StateResult{int state=RTW88_STATE_IDLE;};
struct apple80211_scan_data{unsigned version=1,ssid_len=0,num_channels=0;};
struct apple80211_noise_data{
 unsigned version,num_radios,noise_unit;
 int noise[4],aggregate_noise,noise_ext[4],aggregate_noise_ext;
};
struct ScanBackend{
 int state=RTW88_STATE_IDLE,ret=0;unsigned scans=0;
 int cmdGetState(RTW88StateResult *p){p->state=state;return 0;}
 int cmdScan(){++scans;return ret;}
 RTW88LinkNoise::Reading linkNoise(){return {-87,RTW88LinkNoise::Source::RxSNR};}
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
 const char *noiseSource=nullptr;
 void setProperty(const char *name,const char *value){
  assert(!strcmp(name,"STA_LINK_NOISE_SOURCE"));noiseSource=value;
 }
 IOReturn handleSCAN_REQ(void*);IOReturn scanMultiple(bool);
 IOReturn getNoise(bool,void *);
};
struct Hw;struct Ops{void(*cancel_hw_scan)(Hw*,void*);};struct Hw{Ops *ops;};
constexpr unsigned RX_FLAG_FAILED_FCS_CRC=1,RX_FLAG_NO_SIGNAL_VAL=2,RX_FLAG_DECRYPTED=4;
#include "rtw88_rx_security.h"
enum {RATE_INFO_BW_20,RATE_INFO_BW_40,RATE_INFO_BW_80};
uint64_t jiffies=10000;
struct ieee80211_rx_status{unsigned flag=0;int signal=-42;
 unsigned bw=RATE_INFO_BW_20,freq=5180;uint8_t rtw_snr_half_db=0;};
struct ieee80211_hdr{__le16 frame_control;};
struct sk_buff{
 unsigned len=24;alignas(8) uint8_t storage[64]={};uint8_t *data=storage;
 ieee80211_rx_status status;bool freed=false;
};
unsigned frees=0,signals=0,management=0,dataFrames=0,awdlFrames=0;
bool awdlConsumes=false;
void kfree_skb(sk_buff *s){assert(s&&!s->freed);s->freed=true;++frees;}
ieee80211_rx_status *IEEE80211_SKB_RXCB(sk_buff *s){return &s->status;}
bool matchesAP=true;
bool rtw88StationSignal(const uint8_t*,unsigned,const uint8_t*,const uint8_t*,int,bool invalid){
 ++signals;return !invalid&&matchesAP;
}
bool ieee80211_is_mgmt(__le16 fc){return (fc&12)==0;}
bool ieee80211_is_data(__le16 fc){return (fc&12)==8;}
struct RTW88IEEE80211{
 unsigned _authAttempts=0;bool roamScanActive()const{return false;}void roamTrace(const char*,unsigned=0){}
 int _state=RTW88_STATE_IDLE,_rssi=-80;
 bool _enterprise=false,_enterpriseAuthorized=false,_manualScanAbort=false,canceled=false;
 unsigned _manualScanChannelCount=0,_rxFrameCount=0,completions=0,disconnects=0,failures=0;
 uint8_t _macAddr[6]={};struct{uint8_t bssid[6]={};unsigned freq=5180;}_targetBSS;
 bool _associatedVisible=false,_awdlOffChannel=false,_rxNoiseSupported=true;
 uint8_t _connChanWidth=80;
 uint64_t _rxNoiseSample=0;
 RTW88LinkNoise::Reading linkNoise() const;
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
 struct Chip{unsigned id=0,rx_pkt_desc_sz=24;} spec;
 Chip *chip=&spec;
 bool mutex=false,need_rfk=true;unsigned long flags[1]={1};struct{int fix_rate=0;}dm_info;
};
using u8=uint8_t;
enum {RTW_CHIP_TYPE_8821C=1,RX_DESC_ENC_AES=4,RTW_RX_DESC_W0_ENC_TYPE=15};
struct rtw_rx_desc{uint32_t w0=0;};
struct rtw_rx_pkt_stat{
 bool is_c2h=false,phy_status=true,crc_err=false,icv_err=false,decrypted=false;
 unsigned drv_info_sz=32,shift=3;
};
unsigned le32_get_bits(uint32_t value,unsigned mask){return value&mask;}
void rtw88_original_rx_query_rx_desc(rtw_dev *, void *, rtw_rx_pkt_stat *stat,
                                     ieee80211_rx_status *status) {
 if (!stat->is_c2h) *status={};
}
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
 {
  AirPortRTW controller;
  apple80211_noise_data noise={};
  assert(controller.getNoise(false,&noise)==6 && !controller.noiseSource);
  controller.backend.state=RTW88_STATE_CONNECTED;
  assert(controller.getNoise(true,&noise)==kIOReturnUnsupported);
  assert(controller.getNoise(false,&noise)==0);
  assert(noise.num_radios==1 && noise.noise_unit==APPLE80211_UNIT_DBM);
  assert(noise.noise[0]==-87 && noise.aggregate_noise==-87);
  assert(!strcmp(controller.noiseSource,"rx-snr"));
 }
 {
  rtw_dev dev;dev.chip->id=RTW_CHIP_TYPE_8821C;
  struct {rtw_rx_desc descriptor;u8 rest[24+3+32-sizeof(rtw_rx_desc)]={};} buffer;
  auto *phy=reinterpret_cast<u8 *>(&buffer)+24+3;
  rtw_rx_pkt_stat stat;
  ieee80211_rx_status status;
  auto captured=[&](){
   status.rtw_snr_half_db=99;
   rtw_rx_query_rx_desc(&dev,&buffer.descriptor,&stat,&status);
   return status.rtw_snr_half_db;
  };
  phy[0]=0x21;phy[24]=62;assert(captured()==62);
  phy[0]=0x20;assert(captured()==0);phy[0]=0x21;
  phy[24]=0xff;assert(captured()==0);phy[24]=62;
  stat.drv_info_sz=24;assert(captured()==0);stat.drv_info_sz=32;
  stat.is_c2h=true;assert(captured()==0);stat.is_c2h=false;
  stat.phy_status=false;assert(captured()==0);stat.phy_status=true;
  stat.crc_err=true;assert(captured()==0);stat.crc_err=false;
  stat.icv_err=true;assert(captured()==0);stat.icv_err=false;
  dev.chip->id=0;assert(captured()==0);
 }
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
 using Source=RTW88LinkNoise::Source;
 receiver._associatedVisible=true;
 receiver._state=RTW88_STATE_CONNECTED;
 const auto expectNoise=[&](int dbm,Source source){
  const auto noise=receiver.linkNoise();assert(noise.dbm==dbm&&noise.source==source);
 };
 const auto receive=[&](unsigned freq,unsigned width,int signal,uint8_t snr){
  sk_buff frame;frame.status={0,signal,width,freq,snr};receiver.rxFrame(&frame);
 };
 expectNoise(-89,Source::ThermalEstimate);
 receive(5180,RATE_INFO_BW_80,-54,62);
 expectNoise(-85,Source::RxSNR);
 jiffies+=RTW88LinkNoise::MaxSampleAgeMs+1;
 expectNoise(-89,Source::ThermalEstimate);
 receive(5200,RATE_INFO_BW_80,-54,62);
 receive(5180,RATE_INFO_BW_20,-54,62);
 receive(5180,RATE_INFO_BW_80,-54,0);
 receive(5180,RATE_INFO_BW_80,-54,12);
 receiver._awdlOffChannel=true;receive(5180,RATE_INFO_BW_80,-54,62);
 receiver._awdlOffChannel=false;
 receiver._state=RTW88_STATE_SCANNING;receive(5180,RATE_INFO_BW_80,-54,62);
 receiver._state=RTW88_STATE_CONNECTED;
 matchesAP=false;receive(5180,RATE_INFO_BW_80,-54,62);matchesAP=true;
 expectNoise(-89,Source::ThermalEstimate);
 receiver._connChanWidth=40;expectNoise(-92,Source::ThermalEstimate);
 receiver._connChanWidth=20;expectNoise(-95,Source::ThermalEstimate);
 receiver._connChanWidth=80;receiver._rxNoiseSupported=false;expectNoise(-95,Source::Fixed);
 std::puts("PASS: scan and RX regressions, RTL8821C SNR capture, link-noise validation and fallback");
}
'''
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    (path / 'test.cpp').write_text('#include <initializer_list>\n' + pre +
                                  scan + multi + noise_query + timer + rx + noise + descriptor + restore + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I', str(root / 'src/kext'), '-I', str(root / 'src/compat'),
                    '-g', str(path / 'test.cpp'), '-o', str(path / 'test')],
                   check=True, timeout=60)
    subprocess.run([str(path / 'test')], check=True, timeout=30,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
