#!/usr/bin/env python3
"""Production SAE worker/RX/clear serialization and stale-worker fencing.
Crypto is checked separately by real SAE loss/retry tests; RF/OS are mocked.
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

methods = ''.join(method(s) for s in (
    'bool RTW88IEEE80211::wpa3Auth()',
    'void RTW88IEEE80211::wpa3ReceiveAuth(',
    'void RTW88IEEE80211::failJoin(',
    'void RTW88IEEE80211::clearWPA3()'))
pre = r'''
#include "RTW88WPA3.hpp"
#include <cassert>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
struct IOLock{std::mutex mutex;};thread_local IOLock*held=nullptr;
void IOLockLock(IOLock*l){assert(!held);l->mutex.lock();held=l;}
void IOLockUnlock(IOLock*l){assert(held==l);held=nullptr;l->mutex.unlock();}
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_AUTHENTICATING=2,RTW88_STATE_ASSOCIATING=3;
constexpr int kRTW88EventDisconnected=3,kIONetworkLinkValid=1;
void IOLog(const char*,...){}
std::atomic<bool>entered{false},releaseAuth{false};
struct Session{
 IOLock*lock=nullptr;bool active=false,committed=false,confirmed=false,block=false,bad=false;
 unsigned stage=0,error=0,next=2,receives=0,auths=0;uint8_t confirm[34]={};
 bool begin(const uint8_t*,const uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t){assert(held==lock);active=true;return true;}
 size_t auth(uint8_t*out){assert(held==lock);++auths;if(block){entered=true;while(!releaseAuth)std::this_thread::yield();}
  RTW88WPA3::put(out,3);RTW88WPA3::put(out+2,committed?2:1);RTW88WPA3::put(confirm,auths);return 40;}
 unsigned receiveAuth(const uint8_t*,size_t){assert(held==lock);++receives;
  if(bad){error=0x20000;return 0;}
  if(next==RTW88WPA3::AuthRejected){active=committed=confirmed=false;error=0x4000f;return next;}
  committed=true;if(next==2)confirmed=true;return next;}
 void clear(){assert(held==lock);active=committed=confirmed=false;stage=error=0;}
};
struct Timer{unsigned cancelled=0;void cancelTimeout(){++cancelled;}};
struct Parent{void setLinkStatus(int){assert(!held);}};
struct Delegate{unsigned pending=0;bool deferWorkerEvent(int,unsigned,unsigned){assert(!held);++pending;return true;}void rtw88Event(int,void*){assert(false);}};
struct RTW88IEEE80211{
 IOLock lock;IOLock*_lock=&lock;Session _sae;bool _saeMode=true;
 bool _connectCancelled=false,_disconnectVoluntary=true,_associatedVisible=true;
 unsigned _scanGeneration=1,_authAttempts=1;
 Parent parent;Parent*_parent=&parent;Delegate delegate;Delegate*_delegate=&delegate;
 std::atomic<int>_state{RTW88_STATE_AUTHENTICATING};std::atomic<bool>cancelled{false};
 uint8_t _macAddr[6]={2,1,2,3,4,5};char _password[64]="password";unsigned _txSeq=0;
 struct{uint8_t bssid[6]={2,6,7,8,9,10};char ssid[33]="test";unsigned ssid_len=4;uint8_t ies[512]={};size_t ies_len=0;}_targetBSS;
 Timer timer;Timer*_timer=&timer;unsigned tx=0,associations=0,failures=0;
 RTW88IEEE80211(){_sae.lock=_lock;}
 bool authenticationCancelled()const{return cancelled||__atomic_load_n(&_connectCancelled,__ATOMIC_ACQUIRE);}
 void roamTrace(const char*s,unsigned=0){if(!strcmp(s,"sae-auth-rejected")){assert(!held);++failures;}}
 bool txMgmtFrame(const uint8_t*f,uint32_t n){assert(held==_lock&&n==64&&f[0]==0xb0);++tx;return true;}
 void failJoin(const char*);
 void doAssociate(){assert(!held);++associations;_state=RTW88_STATE_ASSOCIATING;}
 bool wpa3Auth();void wpa3ReceiveAuth(const uint8_t*,uint32_t);void clearWPA3();
};
'''
cases = r'''
int main(){
 uint8_t frame[64]={};
 // The controller can hold its gate while joining an auth worker. The SAE
 // lock must not cause that worker to enter or wait for the controller gate.
 std::mutex controllerGate;std::lock_guard<std::mutex>controller(controllerGate);
 RTW88IEEE80211 b;b._sae.block=true;
 std::thread worker([&]{assert(b.wpa3Auth());});
 auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
 while(!entered){assert(std::chrono::steady_clock::now()<deadline);std::this_thread::yield();}
 std::atomic<bool>rxStarted{false},rxFinished{false};
 std::thread rx([&]{rxStarted=true;b.wpa3ReceiveAuth(frame,64);rxFinished=true;});
 while(!rxStarted)std::this_thread::yield();
 std::this_thread::sleep_for(std::chrono::milliseconds(10));assert(!rxFinished);
 releaseAuth=true;worker.join();rx.join();
 assert(b.tx==1&&b.associations==1&&b._sae.receives==1&&b._sae.confirmed);
 assert(b.wpa3Auth()&&b.tx==1); // stale retry cannot transmit after ASSOC
 b.clearWPA3();assert(!b._saeMode&&!b._sae.active&&!b._sae.confirmed);
 // Receiving a peer Commit unlocks before sending our Confirm, using a
 // non-recursive lock. Failed proofs never start association.
 RTW88IEEE80211 commit;commit._sae.active=true;commit._sae.next=1;
 commit.wpa3ReceiveAuth(frame,64);assert(commit.tx==1&&!commit.associations);
 commit._sae.bad=true;commit.wpa3ReceiveAuth(frame,64);assert(commit.tx==1&&!commit.associations);
 RTW88IEEE80211 cancelled;cancelled.cancelled=true;
 assert(cancelled.wpa3Auth()&&!cancelled.tx&&!cancelled._sae.active);
 cancelled.wpa3ReceiveAuth(frame,64);assert(!cancelled._sae.receives);
 // A received status 15 is a terminal rejection. Use the real failure path,
 // outside the crypto lock, and verify a queued retry cannot begin new SAE.
 RTW88IEEE80211 rejected;rejected._sae.active=rejected._sae.committed=true;
 rejected._sae.next=RTW88WPA3::AuthRejected;rejected.wpa3ReceiveAuth(frame,30);
 assert(rejected.failures==1&&rejected._state==RTW88_STATE_IDLE&&rejected.authenticationCancelled());
 assert(!rejected._associatedVisible&&!rejected._disconnectVoluntary&&!rejected._password[0]);
 assert(rejected.timer.cancelled==1&&rejected.delegate.pending==1&&!rejected.associations&&!rejected.tx);
 assert(rejected.wpa3Auth()&&!rejected._sae.active&&!rejected.tx);
 rejected.wpa3ReceiveAuth(frame,30);assert(rejected._sae.receives==1&&rejected.delegate.pending==1);
 puts("PASS: production SAE worker/RX/clear serialization, gate-safe callbacks, terminal peer rejection cancels timers/retries and retires RUN, stale replies cannot associate/transmit");
}
'''
with tempfile.TemporaryDirectory() as directory:
    p = Path(directory)
    (p / 'test.cpp').write_text(pre + methods + cases)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-pthread',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(root / 'src/kext'), str(p / 'test.cpp'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True, timeout=10,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
