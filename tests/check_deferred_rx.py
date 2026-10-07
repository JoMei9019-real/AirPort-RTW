#!/usr/bin/env python3
"""Exercise the production queue methods with host ownership/locking stubs."""
import pathlib, subprocess, tempfile, os
root=pathlib.Path(__file__).resolve().parents[1]
s=(root/'src/kext/AirPortRTW.cpp').read_text()
methods=s[s.index('bool AirPortRTW::deferRxFrame('):s.index('IOWorkLoop *AirPortRTW::getRxWorkLoop()')]
pre=r'''
#include <mutex>
#include <thread>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <vector>
#include <iostream>
using OSObject = struct Base;
struct Base { virtual ~Base() = default; };
struct sk_buff { unsigned id; };
std::atomic<unsigned> freed{0};
void kfree_skb(sk_buff *s) { if(s) { ++freed; delete s; } }
using IOSimpleLock = std::mutex;
void IOSimpleLockLock(IOSimpleLock *l) { l->lock(); }
void IOSimpleLockUnlock(IOSimpleLock *l) { l->unlock(); }
struct IOInterruptEventSource { std::atomic<unsigned> signals{0};
 void interruptOccurred(void *, void *, int) { ++signals; } };
struct Backend { std::vector<unsigned> received;
 void rxFrame(sk_buff *s) { received.push_back(s->id); kfree_skb(s); } };
class AirPortRTW:public Base {
public:
 std::mutex lock; IOSimpleLock *_deferredRxLock=&lock;
 IOInterruptEventSource source; IOInterruptEventSource *_deferredRxSource=&source;
 sk_buff *_deferredRx[256]={}; unsigned _deferredRxHead=0,_deferredRxCount=0;
 bool _deferredRxEnabled=false, _shutdown=false;
 uint32_t _deferredRxQueued=0,_deferredRxDropped=0,_deferredRxProcessed=0;
 Backend backend; Backend *_ieee80211=&backend;
 bool deferRxFrame(sk_buff *);
 void setRxQueueEnabled(bool);
 static void deferredRxReady(OSObject *, IOInterruptEventSource *, int);
};
'''
post=r'''
int main() {
 AirPortRTW c;
 c.deferRxFrame(new sk_buff{0}); assert(freed==1 && c._deferredRxDropped==1);
 c.setRxQueueEnabled(true);
 for(unsigned i=0;i<300;++i)c.deferRxFrame(new sk_buff{i});
 assert(c._deferredRxCount==256 && c._deferredRxQueued==256);
 AirPortRTW::deferredRxReady(&c,&c.source,0);
 assert(c._deferredRxCount==192 && c.backend.received.size()==64);
 for(unsigned i=0;i<64;++i)c.deferRxFrame(new sk_buff{300+i});
 for(int i=0;i<4;++i)AirPortRTW::deferredRxReady(&c,&c.source,0);
 assert(c._deferredRxCount==0 && c.backend.received.size()==320);
 for(unsigned i=0;i<256;++i)assert(c.backend.received[i]==i);
 for(unsigned i=256;i<320;++i)assert(c.backend.received[i]==300+i-256);
 // Producer must complete while the simulated controller gate is held.
 std::mutex gate; gate.lock();
 std::thread producer([&]{for(unsigned i=0;i<10000;++i)c.deferRxFrame(new sk_buff{i});});
 producer.join(); c.setRxQueueEnabled(false); gate.unlock();
 assert(c._deferredRxCount==0);
 // Race producer against queue close/reopen; ownership remains exactly once.
 std::thread racing([&]{for(unsigned i=0;i<10000;++i)c.deferRxFrame(new sk_buff{i});});
 for(int i=0;i<1000;++i) { c.setRxQueueEnabled(true); c.setRxQueueEnabled(false); }
 racing.join(); c.setRxQueueEnabled(false);
 __atomic_store_n(&c._shutdown,true,__ATOMIC_RELEASE);
 c.setRxQueueEnabled(true);assert(!c._deferredRxEnabled);
 c.deferRxFrame(new sk_buff{1});
 assert(c._deferredRxCount==0 && freed==20366);
 assert(c._deferredRxProcessed+c._deferredRxDropped==freed);
 std::cout<<"PASS: FIFO/wrap, overflow, bounded drain, stop/reopen race, shutdown, ownership and nonblocking producer\n";
}
'''
# Counters count both rejected packets and discarded queued packets.
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d);(p/'test.cpp').write_text(pre+methods+post)
 compiler=os.environ.get('CXX','c++')
 subprocess.run([compiler,'-std=c++17','-pthread','-fsanitize=address,undefined','-fno-omit-frame-pointer','-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
