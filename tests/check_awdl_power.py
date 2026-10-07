#!/usr/bin/env python3
"""Run production AWDL power/queue methods against host timer/ownership stubs."""
import pathlib, subprocess, tempfile, os
root = pathlib.Path(__file__).resolve().parents[1]
s = (root/'src/kext/RTW88AWDLManager.cpp').read_text()
def method(name):
    import re
    match = re.search(r'(?:void|bool) RTW88AWDLManager::'+name+r'\([^\n]*\)\n\{', s)
    start = match.start(); pos = s.index('{', match.start()); depth = 1; end = pos+1
    while depth:
        if s[end] == '{': depth += 1
        elif s[end] == '}': depth -= 1
        end += 1
    return s[start:end]+'\n'
pre = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <iostream>
struct Packet { unsigned length; uint8_t dst; };
using mbuf_t = Packet *;
unsigned freed = 0;
void mbuf_freem(mbuf_t m) { ++freed; delete m; }
size_t mbuf_pkthdr_len(mbuf_t m) { return m->length; }
int mbuf_copydata(mbuf_t m, int, int, void *p) { *(uint8_t*)p=m->dst; return 0; }
struct Timer { bool armed=false; unsigned arms=0, cancels=0;
 void setTimeoutMS(unsigned) { armed=true; ++arms; }
 void cancelTimeout() { armed=false; ++cancels; } };
struct Backend { bool powered=true; unsigned restores=0;
 bool isPowered() const { return powered; }
 void restoreSTAChannelAfterAWDL() { ++restores; } };
template <typename R, typename F> R awdlGated(std::recursive_mutex *m, void *, F f) {
 std::lock_guard<std::recursive_mutex> guard(*m); return f();
}
struct RTW88AWDLManager {
 std::recursive_mutex gate; std::recursive_mutex *_workLoop=&gate; void *_owner=nullptr;
 Backend backend; Backend *_backend=&backend; Timer timer; Timer *_timer=&timer;
 bool _timerAttached=true, _syncEnabled=true, _powerSuspended=false;
 void *_awdlInterface=this, *_airTemplate=this;
 unsigned _powerSuspends=0, _powerResumes=0, _lastMIFEAW=0; bool _lastMIFEAWValid=false;
 uint64_t _nextActionUS=0,_nextPSFUS=0,_nextSocialSweepUS=0,_fallbackDeadlineUS=0;
 struct Pending { mbuf_t packet=nullptr; uint64_t queuedUS=0; } _pending[128];
 unsigned _queueHead=0,_queueCount=0,_dataDropped=0,_dataEnqueueFailure=0;
 unsigned _dataMulticastQueued=0,_dataUnicastQueued=0,_dataEnqueueSuccess=0,_dataQueueHighWater=0;
 unsigned actionFlushes=0;
 bool powerSuspended() const { return __atomic_load_n(&_powerSuspended,__ATOMIC_ACQUIRE); }
 static uint64_t nowUS() { return 1000; }
 void publishStats() {}
 void flushActions() { assert(powerSuspended() && !timer.armed); ++actionFlushes; }
 void scheduleDiscovery(); void suspendForPowerTransition(); void resumeAfterPowerTransition();
 void arm(uint32_t); bool enqueueData(mbuf_t); void flushData();
};
'''
post = r'''
int main() {
 RTW88AWDLManager m;
 assert(m.enqueueData(new Packet{100,1}));
 assert(m._queueCount==1 && m.timer.armed);
 m.suspendForPowerTransition();
 assert(m.powerSuspended() && !m.timer.armed && m._queueCount==0 && freed==1);
 assert(m.backend.restores==1 && m.actionFlushes==1);
 unsigned arms=m.timer.arms;
 for(unsigned i=0;i<100;++i) { m.scheduleDiscovery(); m.arm(1); }
 assert(m.timer.arms==arms && !m.timer.armed);
 assert(!m.enqueueData(new Packet{100,1}) && freed==2 && m._queueCount==0);
 m.suspendForPowerTransition(); assert(m.backend.restores==1 && m._powerSuspends==1);
 m.backend.powered=false;
 m.resumeAfterPowerTransition(); assert(m.powerSuspended() && m._powerResumes==0);
 m.backend.powered=true;
 m.resumeAfterPowerTransition(); assert(!m.powerSuspended() && m.timer.armed && m._powerResumes==1);
 m.resumeAfterPowerTransition(); assert(m._powerResumes==1);
 assert(m.enqueueData(new Packet{100,1}));
 // Late discovery races with suspend: the shared gate orders cancel and re-arm.
 std::thread late([&]{ for(int i=0;i<10000;++i)m.scheduleDiscovery(); });
 m.suspendForPowerTransition(); late.join();
 assert(m.powerSuspended() && !m.timer.armed && m._queueCount==0 && freed==3);
 m.backend.powered=false; arms=m.timer.arms;
 m.scheduleDiscovery(); m.arm(1); m.resumeAfterPowerTransition();
 assert(m.timer.arms==arms && m.powerSuspended());
 std::cout << "PASS: suspend cancels timers/flushes ownership, blocks late re-arm/enqueue, idempotent stop, powered-only resume, discovery/suspend race\n";
}
'''
methods=''.join(method(n) for n in ['scheduleDiscovery','suspendForPowerTransition','resumeAfterPowerTransition','arm','flushData','enqueueData'])
with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d); (p/'test.cpp').write_text(pre+methods+post)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-pthread','-fsanitize=address,undefined','-fno-omit-frame-pointer','-g',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
