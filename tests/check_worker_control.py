#!/usr/bin/env python3
"""Production off/abort/failure/scan completion with a held controller gate.
RF and Apple are mocked; actual worker threads must finish before gate release.
"""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
b=(root/'src/kext/RTW88IEEE80211.cpp').read_text();c=(root/'src/kext/AirPortRTW.cpp').read_text()
def method(s,sig):
 a=s.index(sig);e=s.index('{',a)+1;d=1
 while d:d+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[a:e]+'\n'
methods=''.join(method(b,x) for x in ['void RTW88IEEE80211::failJoin(', 'void RTW88IEEE80211::scanDone(', 'void RTW88IEEE80211::resumeDeferredJoin(', 'bool RTW88IEEE80211::abortActiveScan(', 'IOReturn RTW88IEEE80211::cmdPowerOffGated()'])+''.join(method(c,x) for x in ['bool AirPortRTW::deferWorkerEvent(', 'void AirPortRTW::drainWorkerEvents()'])
# Control completions must run even while Wi-Fi-off disables deferred data RX.
dispatch=method(c,'void AirPortRTW::deferredRxReady(')
assert dispatch.index('drainWorkerEvents()')<dispatch.index('_deferredRxEnabled')
pre=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
using IOReturn=int;using UInt32=uint32_t;using RTW88State=int;
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_SCANNING=1,RTW88_STATE_AUTHENTICATING=2,RTW88_STATE_ASSOCIATING=3,RTW88_STATE_HANDSHAKING=4,RTW88_STATE_CONNECTED=5;
constexpr int kRTW88EventScanDone=0,kRTW88EventDisconnected=3,kIOReturnSuccess=0,kIOReturnBusy=1,kIONetworkLinkValid=1;
using RTW88Event=int;using IOSimpleLock=std::mutex;
void IOSimpleLockLock(IOSimpleLock*p){p->lock();}void IOSimpleLockUnlock(IOSimpleLock*p){p->unlock();}
void IOLockLock(void*){}void IOLockUnlock(void*){}void IOFree(void*p,size_t){free(p);}
void IOLog(const char*,...){}void bzero(void*p,size_t n){memset(p,0,n);}
void IOSleep(unsigned){std::this_thread::sleep_for(std::chrono::milliseconds(1));}
uint64_t mach_absolute_time(){return 1000000;}void absolutetime_to_nanoseconds(uint64_t t,uint64_t*n){*n=t;}
size_t strlcpy(char*d,const char*s,size_t n){size_t z=strlen(s);if(n){size_t copy=z<n-1?z:n-1;memcpy(d,s,copy);d[copy]=0;}return z;}
struct IOInterruptEventSource{std::atomic<unsigned>signals{0};void interruptOccurred(void*,void*,int){++signals;}};
struct RTW88IEEE80211;
std::recursive_mutex mainGate;
struct AirPortRTW{
 struct WorkerEvent{bool pending=false;uint32_t generation=0,result=0;};WorkerEvent _workerEvents[2]{};
 std::mutex lock;IOSimpleLock*_deferredRxLock=&lock;IOInterruptEventSource source;IOInterruptEventSource*_deferredRxSource=&source;
 bool _shutdown=false;RTW88IEEE80211*_ieee80211=nullptr;void*_netif=this;
 bool rx=true,radio=true;unsigned scanEvents=0,downEvents=0,links=0,lastScan=99;
 bool deferWorkerEvent(RTW88Event,uint32_t,uint32_t);void drainWorkerEvents();
 void setLinkStatus(int){std::lock_guard<std::recursive_mutex>g(mainGate);++links;}
 void rtw88Event(int ev,void*data){std::lock_guard<std::recursive_mutex>g(mainGate);
  if(ev==0){++scanEvents;lastScan=*(UInt32*)data;}else ++downEvents;}
 void scanTxReady(){}void radioPowerChanged(bool value){radio=value;}void setRxQueueEnabled(bool value){rx=value;}
};
struct Timer{void cancelTimeout(){}};
struct Ops{void(*cancel_hw_scan)(void*,void*)=nullptr;};struct Hw{Ops*ops=nullptr;};
struct RTW88BSS{RTW88BSS*next=nullptr;uint8_t bssid[6]={};unsigned last_seen_scan=0;};
struct RTW88IEEE80211{
 AirPortRTW*_parent,*_delegate;
 std::thread auth,scanner;
 bool _connectCancelled=false,_disconnectVoluntary=false,_associatedVisible=false,_powered=true,_manualScanAbort=false,_manualScanOnHomeChannel=false;
 bool _roamScanWorkerPending=false,_roamScanActive=false,_awdlReceiveMode=false;
 volatile int _state=0;int _scanReturnState=0;
 unsigned _manualScanChannelCount=0,_authAttempts=1,_scanGeneration=7,_bssCount=0,_lastScanCacheCount=0,_deauthReason=0,_awdlChannel=0;
 unsigned keyClears=0,staReleases=0,starts=0,stops=0;
 uint64_t _roamScanCompletedMs=0;unsigned _roamScanResult=0;
 Timer timer;Timer*_timer=&timer;void*_bssLock=nullptr;RTW88BSS*_bssList=nullptr;Hw*_hw=nullptr;void*_vif=nullptr;
 struct{uint8_t bssid[6]={};}_targetBSS;
 bool _deferredConnectPending=false,_deferredPMKValid=false,_deferredBSSIDValid=false,_deferredExternalSupplicant=false,_deferredSAE=false;
 char _deferredSSID[33]={},_deferredPassword[64]={};uint8_t _deferredPMK[32]={},_deferredBSSID[6]={};
 RTW88IEEE80211(AirPortRTW&c):_parent(&c),_delegate(&c){c._ieee80211=this;}
 ~RTW88IEEE80211(){if(auth.joinable())auth.join();if(scanner.joinable())scanner.join();}
 void cancelRoamSwitch(){}void roamTrace(const char*,unsigned=0){}void wakeTrace(const char*){}
 bool roamScanActive()const{return _roamScanActive;}
 unsigned scanGeneration()const{return _scanGeneration;}int rawState()const{return _state;}
 bool associatedVisible()const{return _associatedVisible;}bool joinCancelled()const{return _connectCancelled;}
 void cancelAuthentication(){_connectCancelled=true;if(auth.joinable())auth.join();}
 void clearDeferredJoin(){_deferredConnectPending=false;}
 void clearKeys(){assert(!auth.joinable());++keyClears;}void releaseSta(){++staReleases;}
 void doDisconnect(){clearKeys();releaseSta();_state=0;_associatedVisible=false;}
 void powerOff(){assert(!_manualScanChannelCount&&!_roamScanWorkerPending);_powered=false;++stops;}
 void clearAssocRsnIE(){}void restoreConnectedChannel(){}void txNullFunc(bool){}
 int setAWDLChannel(unsigned){return 0;}int setAWDLReceiveMode(bool){return 0;}
 int cmdConnect(const char*,const char*,const uint8_t*,const uint8_t*,bool,bool){++starts;_state=2;return 0;}
 void failJoin(const char*);void scanDone(bool);void resumeDeferredJoin();bool abortActiveScan(bool);int cmdPowerOffGated();
};
'''
cases=r'''
int main(){
 // Auth worker's failure used to block in setLinkStatus(mainGate) while the
 // main gate holder waited for that very worker in cancelAuthentication().
 {AirPortRTW c;RTW88IEEE80211 b(c);b._state=2;
  std::lock_guard<std::recursive_mutex>g(mainGate);
  b.auth=std::thread([&]{std::this_thread::sleep_for(std::chrono::milliseconds(5));b.failJoin("auth-timeout");});
  assert(b.cmdPowerOffGated()==0&&!b._powered&&!c.rx&&!c.radio&&b.stops==1);
  assert(c.downEvents==0&&c._workerEvents[1].pending);
  c.drainWorkerEvents();assert(c.downEvents==1);
 }
 // Scan worker must be able to queue completion and release ownership while
 // the main gate holder waits in abortActiveScan(), with data RX disabled.
 {AirPortRTW c;RTW88IEEE80211 b(c);b._state=1;b._scanReturnState=0;
  b._manualScanChannelCount=39;b._roamScanWorkerPending=true;b._deferredConnectPending=true;
  std::lock_guard<std::recursive_mutex>g(mainGate);
  b.scanner=std::thread([&]{std::this_thread::sleep_for(std::chrono::milliseconds(5));
   b.scanDone(true);b._manualScanChannelCount=0;__atomic_store_n(&b._roamScanWorkerPending,false,__ATOMIC_RELEASE);});
  assert(b.cmdPowerOffGated()==0&&!b._powered&&!b.starts&&b.stops==1);
  b.scanner.join();assert(c.scanEvents==0&&c._workerEvents[0].pending);
  c.drainWorkerEvents();assert(c.scanEvents==1&&c.lastScan==1&&!b.starts);
 }
 // Normal accepted scan-time join starts only after Apple SCAN_DONE, on loop.
 {AirPortRTW c;RTW88IEEE80211 b(c);b._state=1;b._deferredConnectPending=true;
  strcpy(b._deferredSSID,"test");b.scanDone(false);assert(!b.starts&&!c.scanEvents);
  c.drainWorkerEvents();assert(b.starts==1&&c.scanEvents==1);
 }
 // Stale scan/failure completions cannot finish a newer scan or drop a join.
 {AirPortRTW c;RTW88IEEE80211 b(c);b._state=2;b._connectCancelled=false;
  assert(c.deferWorkerEvent(3,7,0));c.drainWorkerEvents();assert(!c.downEvents&&!c.links);
  assert(c.deferWorkerEvent(0,7,1));b._scanGeneration=8;c.drainWorkerEvents();assert(!c.scanEvents);
  c._shutdown=true;assert(c.deferWorkerEvent(3,8,0)&&!c._workerEvents[1].pending);
  assert(!c.deferWorkerEvent(99,8,0));
 }
 // A genuinely stuck software worker still keeps ownership and radio/RX on.
 {AirPortRTW c;RTW88IEEE80211 b(c);b._state=1;b._manualScanChannelCount=39;b._roamScanWorkerPending=true;
  std::lock_guard<std::recursive_mutex>g(mainGate);
  assert(b.cmdPowerOffGated()==kIOReturnBusy&&b._powered&&c.rx&&c.radio&&!b.stops&&!b.keyClears);
  b._manualScanChannelCount=0;b._roamScanWorkerPending=false;
 }
 puts("PASS: production power-off joins auth/scan workers with controller gate held, defers Apple/link callbacks, completes scans with RX off, orders deferred joins, filters stale events and retains stuck-worker resources");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run(['c++','-std=c++17','-pthread','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=10,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
