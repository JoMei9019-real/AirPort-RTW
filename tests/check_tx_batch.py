#!/usr/bin/env python3
"""Production batch scope, submission tail and HCI bridge with mocked DMA.
This proves ownership/flush policy, not RF throughput or Apple queue scheduling.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
cpp = (root / 'src/kext/RTW88IEEE80211.cpp').read_text()
compat = (root / 'src/compat/rtw88_compat.c').read_text()
controller = (root / 'src/kext/AirPortRTW.cpp').read_text()

def method(source, signature):
    start = source.index(signature)
    pos = source.index('{', start)
    depth, end = 1, pos + 1
    while depth:
        if source[end] == '{': depth += 1
        elif source[end] == '}': depth -= 1
        end += 1
    return source[start:end] + '\n'

methods = ''.join(method(cpp, s) for s in (
    'bool RTW88IEEE80211::beginTxBatch()',
    'void RTW88IEEE80211::flushTxBatch()',
    'void RTW88IEEE80211::endTxBatch()'))
bridge = method(compat, 'int rtw88_tx_batch_write(') + method(compat, 'bool rtw88_tx_batch_flush(')
tail = cpp[cpp.index('    bool submitted = true;', cpp.index('bool RTW88IEEE80211::txDataFrame(')):]
tail = tail[:tail.index('\n}')]
assert 'RTW88TxBatchScope<RTW88IEEE80211> batch(_ieee80211)' in controller
assert controller.index('flushTxBatch();', controller.index('SInt32 AirPortRTW::stopDMA')) < controller.index('__atomic_store_n(&_dmaStopped', controller.index('SInt32 AirPortRTW::stopDMA'))
assert 'flushTxBatch();' in method(cpp, 'void RTW88IEEE80211::powerOffGated()')
assert 'rtw88_tx_batch_write' not in method(cpp, 'bool RTW88IEEE80211::txAWDLDataFrame(')
pre = r'''
#include "RTW88TxBatchScope.hpp"
#include <cassert>
#include <cstdint>
#include <cerrno>
#include <iostream>
constexpr uint16_t ETH_P_PAE=0x888e;
constexpr int RTW_FLAG_RUNNING=0;
using thread_t=uintptr_t;
thread_t threadId=1;
uintptr_t rtw88_tx_thread_id(){return threadId;}
struct sk_buff { bool freed=false; };
struct ieee80211_sta {};
struct rtw_tx_pkt_info { int unused; };
struct rtw_dev { unsigned long flags[1]={1}; };
struct ieee80211_tx_control { ieee80211_sta *sta; };
struct ieee80211_hw;
struct Ops { void (*tx)(ieee80211_hw*,ieee80211_tx_control*,sk_buff*); };
struct ieee80211_hw { rtw_dev *priv; Ops *ops; };
int freed=0,writes=0,kicks=0,pending=0,retCode=0,maxPending=0;
bool test_bit(int,unsigned long *p){return *p&1;}
void ieee80211_free_txskb(ieee80211_hw*,sk_buff *s){assert(s&&!s->freed);s->freed=true;++freed;}
void rtw_tx_pkt_info_update(rtw_dev*,rtw_tx_pkt_info*,ieee80211_sta*,sk_buff*){}
int rtw_hci_tx_write(rtw_dev*,rtw_tx_pkt_info*,sk_buff*){
 ++writes;if(retCode)return retCode;
 ++pending;if(pending>maxPending)maxPending=pending;return 0;}
void rtw_hci_tx_kick_off(rtw_dev*){++kicks;pending=0;}
void normalTx(ieee80211_hw*h,ieee80211_tx_control*c,sk_buff*s){
 rtw_tx_pkt_info info{};int r=rtw_hci_tx_write(h->priv,&info,s);
 if(r)ieee80211_free_txskb(h,s);else rtw_hci_tx_kick_off(h->priv);}
struct Mbuf{};using mbuf_t=Mbuf*;
void mbuf_freem(mbuf_t){}
struct RTW88IEEE80211 {
 bool _powered=true,_txBatchEnabled=true,_txBaActive=true;
 ieee80211_hw *_hw;ieee80211_sta *_sta=nullptr;
 uintptr_t _txBatchOwner=0;
 uint32_t _txBatchPending=0,_txBatchFrames=0,_txBatchFlushes=0;
 bool beginTxBatch();void endTxBatch();void flushTxBatch();
 bool submit(sk_buff*,uint16_t,bool=true);
};
'''
submit = 'bool RTW88IEEE80211::submit(sk_buff *skb,uint16_t ethertype,bool qos){\nmbuf_t m=nullptr;ieee80211_tx_control ctrl{_sta};\n' + tail + '\n}\n'
post = r'''
int main(){
 Ops ops{normalTx};rtw_dev dev;ieee80211_hw hw{&dev,&ops};RTW88IEEE80211 b;b._hw=&hw;
 // Batches of 1,31,32,33,64: final remainder always kicked; no timer.
 for(int count:{1,31,32,33,64}){
  int before=kicks;maxPending=0;
  {RTW88TxBatchScope<RTW88IEEE80211> scope(&b);
   for(int n=0;n<count;++n){sk_buff s;assert(b.submit(&s,0x800));assert(!s.freed);}}
  assert(pending==0&&b._txBatchPending==0&&b._txBatchOwner==0);
  assert(kicks-before==(count+31)/32&&maxPending<=32);
 }
 // EAPOL flushes earlier data immediately, even without leaving the scope.
 {RTW88TxBatchScope<RTW88IEEE80211> scope(&b);sk_buff a,e;
  assert(b.submit(&a,0x800)&&pending==1);int before=kicks;
  assert(b.submit(&e,ETH_P_PAE));assert(kicks==before+1&&pending==0);}
 // Error/ring-full frees only the rejected skb and kicks older descriptors.
 {RTW88TxBatchScope<RTW88IEEE80211> scope(&b);sk_buff a,failed;
  assert(b.submit(&a,0x800));retCode=-ENOSPC;
  assert(!b.submit(&failed,0x800)&&failed.freed&&!a.freed&&pending==0);retCode=0;}
 // Early return/exception unwinding through the same RAII guard.
 auto stalled=[&](){RTW88TxBatchScope<RTW88IEEE80211> scope(&b);sk_buff a;b.submit(&a,0x800);return -1;};
 assert(stalled()==-1&&pending==0&&b._txBatchOwner==0);
 {RTW88TxBatchScope<RTW88IEEE80211> outer(&b);sk_buff a;b.submit(&a,0x800);
  int before=kicks;{RTW88TxBatchScope<RTW88IEEE80211> nested(&b);}
  assert(kicks==before&&b._txBatchOwner==1);}
 // A different execution thread never acquires/defer-kicks in our scope.
 {RTW88TxBatchScope<RTW88IEEE80211> scope(&b);sk_buff a,c;b.submit(&a,0x800);
  threadId=2;assert(!b.beginTxBatch());b.submit(&c,0x800);assert(pending==0);
  b.endTxBatch();assert(b._txBatchOwner==1);threadId=1;}
 // A/B disabled and no BA/QoS use the original immediate-doorbell behavior.
 b._txBatchEnabled=false;assert(!b.beginTxBatch());
 {sk_buff s;int k=kicks;b.submit(&s,0x800);assert(kicks==k+1);}
 b._txBatchEnabled=true;
 {RTW88TxBatchScope<RTW88IEEE80211> scope(&b);sk_buff s,t;
  b._txBaActive=false;b.submit(&s,0x800);assert(!pending);
  b._txBaActive=true;b.submit(&t,0x800,false);assert(!pending);}
 // Before power-off, flush while the device is still running. After stop,
 // even an explicit flush cannot access MMIO or double-free a rejected skb.
 {RTW88TxBatchScope<RTW88IEEE80211> scope(&b);sk_buff s;b.submit(&s,0x800);b.flushTxBatch();assert(!pending);}
 dev.flags[0]=0;int k=kicks,w=writes;sk_buff stopped;
 assert(rtw88_tx_batch_write(&hw,nullptr,&stopped,false)==-ESHUTDOWN&&stopped.freed);
 assert(!rtw88_tx_batch_flush(&hw)&&kicks==k&&writes==w);
 b._powered=false;assert(!b.beginTxBatch());
 std::cout<<"PASS: production batch/HCI paths, 32-frame bound, partial/error flush, EAPOL, nested/foreign scopes, disabled mode, stopped-device ownership\n";
}
'''
with tempfile.TemporaryDirectory() as td:
    p = Path(td); (p/'batch.cpp').write_text(pre+bridge+methods+submit+post)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer','-I'+str(root/'src/kext'),str(p/'batch.cpp'),'-o',str(p/'batch')],check=True)
    subprocess.run([str(p/'batch')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
