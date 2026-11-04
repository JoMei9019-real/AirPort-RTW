#!/usr/bin/env python3
"""Production scan drain must outlast CONNECTED publication, under mocked time."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'src/kext/RTW88IEEE80211.cpp').read_text();a=s.index('bool RTW88IEEE80211::abortActiveScan(');e=s.index('{',a)+1;d=1
while d:d+=(s[e]=='{')-(s[e]=='}');e+=1
method=s[a:e]+'\n'
pre=r'''
#include <cassert>
#include <cstdio>
using RTW88State=int;
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_SCANNING=1,RTW88_STATE_CONNECTED=5;
struct Hw;void cancel(Hw*,void*);
struct Ops{void(*cancel_hw_scan)(Hw*,void*)=cancel;};struct Hw{Ops*ops;};
unsigned sleeps=0,cancels=0,scenario=0;
void IOSleep(unsigned);
struct RTW88IEEE80211{
 int _state=1,_scanReturnState=5;unsigned _manualScanChannelCount=39,restores=0;
 bool _roamScanWorkerPending=true,_manualScanAbort=false,_manualScanOnHomeChannel=true;
 Ops ops;Hw hw{&ops};Hw*_hw=&hw;void*_vif=this;
 void restoreConnectedChannel(){++restores;}
 bool abortActiveScan(bool);
};
RTW88IEEE80211*active;
void cancel(Hw*,void*){++cancels;}
void IOSleep(unsigned n){assert(n==50);++sleeps;
 if(scenario==1||scenario==2){active->_state=5;active->_scanReturnState=0;}
 if(scenario==1&&sleeps==4){active->_manualScanChannelCount=0;active->_roamScanWorkerPending=false;}
}
'''
cases=r'''
int main(){
 RTW88IEEE80211 b;active=&b;scenario=1;
 assert(b.abortActiveScan(true)&&b._manualScanAbort&&sleeps==4&&!b.restores&&!cancels);
 RTW88IEEE80211 stuck;active=&stuck;scenario=2;sleeps=0;
 assert(!stuck.abortActiveScan(true)&&sleeps==40&&stuck._state==5&&stuck._roamScanWorkerPending&&!stuck.restores);
 // Also drain the tail after scanDone already published CONNECTED at entry.
 RTW88IEEE80211 tail;tail._state=5;tail._scanReturnState=0;active=&tail;scenario=1;sleeps=0;
 assert(tail.abortActiveScan(true)&&sleeps==4);
 RTW88IEEE80211 async;active=&async;sleeps=0;
 assert(async.abortActiveScan(false)&&async._manualScanAbort&&!sleeps&&async._manualScanChannelCount==39);
 RTW88IEEE80211 firmware;firmware._manualScanChannelCount=0;firmware._roamScanWorkerPending=false;
 active=&firmware;scenario=0;sleeps=0;cancels=0;
 assert(firmware.abortActiveScan(true)&&sleeps==40&&cancels==1&&firmware._state==5&&firmware.restores==1);
 RTW88IEEE80211 idle;idle._state=0;idle._manualScanChannelCount=0;idle._roamScanWorkerPending=false;
 active=&idle;sleeps=0;assert(idle.abortActiveScan(true)&&!sleeps);
 puts("PASS: production scan abort waits for worker after CONNECTED, retains stuck-worker ownership, bounds wait and preserves firmware/async completion");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+method+cases)
 subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
