#!/usr/bin/env python3
"""Execute production BTM queue, response, ACK gate, scan and switch paths."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
fixture=(root/'tests/check_roam_diagnostics.py').read_text()
ns={'__file__':str(root/'tests/check_roam_diagnostics.py')}
exec(compile(fixture[:fixture.index("\ncases=r'''")],str(root/'tests/check_roam_diagnostics.py'),'exec'),ns)
pre,method,methods=ns['pre'],ns['method'],ns['methods']
pre=pre.replace('void cancelBTM(const char*){_btmPhase=0;}','void cancelBTM(const char*);')
pre=pre.replace('void queueBtm(const BtmRequest&,uint64_t){}',r'''
 void queueBtm(const BtmRequest&,uint64_t);void btmTick(uint64_t);
 bool sendBtmResponse(uint8_t,uint8_t,const uint8_t* =nullptr);
 void rejectBtm(uint8_t,const char*);bool selectBtmTarget(uint64_t,uint8_t[6]);
 void observeBtmTx(const uint8_t*,uint32_t,bool);
''')
methods+=''.join(method(s) for s in (
 'void RTW88IEEE80211::cancelBTM(', 'bool RTW88IEEE80211::sendBtmResponse(',
 'void RTW88IEEE80211::rejectBtm(', 'void RTW88IEEE80211::queueBtm(',
 'bool RTW88IEEE80211::selectBtmTarget(', 'void RTW88IEEE80211::observeBtmTx(',
 'void RTW88IEEE80211::btmTick('))
cases=r'''
uint8_t ies[]={70,5,2,0,0,0,0,127,3,0,0,8,48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
void init(RTW88IEEE80211 &b,Hw &hw,RTW88BSS &candidate,uint64_t now) {
 b._hw=&hw;b._bssList=&candidate;b._rssi=-65;b._targetBSS.channel=6;
 b._roamingAssistEnabled=b._autoRoamEnabled=b._roamingCapsValid=b._stationBTM=true;
 b.parent.btmAvailable=true;b._roaming.ap.btm=true;
 memcpy(b._targetBSS.ies,ies,sizeof(ies));b._targetBSS.ies_len=sizeof(ies);
 memcpy(candidate.ies,ies,sizeof(ies));candidate.ies_len=sizeof(ies);candidate.observedMs=now;candidate.rssi=-40;
}
std::vector<uint8_t> request(RTW88IEEE80211 &b,RTW88BSS &candidate,uint8_t token=11,uint8_t validity=255,uint8_t preference=200) {
 std::vector<uint8_t> f(24);f[0]=0xd0;
 memcpy(f.data()+4,b._macAddr,6);memcpy(f.data()+10,b._targetBSS.bssid,6);memcpy(f.data()+16,b._targetBSS.bssid,6);
 f.insert(f.end(),{10,7,token,1,0,0,validity,52,16});
 f.insert(f.end(),candidate.bssid,candidate.bssid+6);
 f.insert(f.end(),{0,0,0,0,81,candidate.channel,7,3,1,preference});return f;
}
void receive(RTW88IEEE80211 &b,RTW88BSS &candidate,uint64_t now,uint8_t validity=255,uint8_t preference=200) {
 auto f=request(b,candidate,11,validity,preference);b.handleRoamingAction(f.data(),f.size(),now);
}
int main() {
 ieee80211_supported_band band;Wiphy w{{&band}};Ops ops;Hw hw{&w,&ops};
 RTW88BSS candidate;RTW88IEEE80211 b;init(b,hw,candidate,1000);
 receive(b,candidate,1000);assert(b._btmPhase==1&&b.parent.scheduled==1&&!b.joins&&b.submitted.empty());
 b.btmTick(1001);assert(b._btmPhase==2&&!b.joins&&b.submitted.size()==1);
 auto reply=b.submitted.back();assert(reply.size()==35&&reply[26]==11&&reply[27]==0&&!memcmp(reply.data()+29,candidate.bssid,6));
 b.btmTick(1010);assert(!b.joins); // acceptance submission is not an ACK
 b.observeBtmTx(reply.data(),reply.size(),true);b.btmTick(1020);
 assert(b.joins==1&&b._roamSwitch.phase==1&&!b._btmPhase);
 assert(b._roamingStats[RTW88Roaming::BtmAcceptTx]==1&&b._roamingStats[RTW88Roaming::BtmSwitchTx]==1);
 // ACK of another sequence cannot authorize a disconnect.
 RTW88IEEE80211 noack;init(noack,hw,candidate,2000);receive(noack,candidate,2000);noack.btmTick(2001);
 auto wrong=noack.submitted.back();wrong[22]^=0x10;
 noack.observeBtmTx(wrong.data(),wrong.size(),true);noack.btmTick(2020);assert(!noack.joins);
 noack.btmTick(2300);assert(!noack._btmPhase&&!noack.joins&&noack._associatedVisible);
 // Failed submission, boot-disabled policy and short validity never join.
 RTW88IEEE80211 txfail;init(txfail,hw,candidate,3000);txfail.txSucceeds=false;
 receive(txfail,candidate,3000);txfail.btmTick(3001);assert(!txfail._btmPhase&&!txfail.joins);
 RTW88IEEE80211 off;init(off,hw,candidate,4000);off._autoRoamEnabled=off._stationBTM=false;
 receive(off,candidate,4000);assert(!off._btmPhase&&off.submitted.back()[27]==1&&!off.joins);
 RTW88IEEE80211 shortlife;init(shortlife,hw,candidate,5000);receive(shortlife,candidate,5000,5);
 assert(!shortlife._btmPhase&&shortlife.submitted.back()[27]==7&&!shortlife.joins);
 // Candidate preference zero and weaker targets are not followed blindly.
 RTW88IEEE80211 excluded;init(excluded,hw,candidate,6000);receive(excluded,candidate,6000,255,0);
 excluded.btmTick(6001);assert(!excluded._btmPhase&&excluded.submitted.back()[27]==7&&!excluded.joins);
 // One bounded target-channel scan, followed by a fresh revalidation.
 RTW88IEEE80211 scan;init(scan,hw,candidate,100000);candidate.observedMs=1;
 receive(scan,candidate,100000);scan.btmTick(100001);assert(scan._btmScanned&&scan._state==1&&!scan.joins);
 candidate.observedMs=100200;scan.runManualScan();scan.btmTick(100300);
 assert(scan._btmPhase==2);reply=scan.submitted.back();scan.observeBtmTx(reply.data(),reply.size(),true);scan.btmTick(100320);
 assert(scan.joins==1&&scan._roamingStats[RTW88Roaming::BtmScanTx]==1);free(scan._scanRequest);
 RTW88IEEE80211 aborted;init(aborted,hw,candidate,110000);candidate.observedMs=1;
 receive(aborted,candidate,110000);aborted.btmTick(110001);aborted._manualScanAbort=true;aborted.runManualScan();aborted.btmTick(110300);
 assert(!aborted._btmPhase&&!aborted.joins&&aborted.submitted.back()[27]==7);free(aborted._scanRequest);
 // PM, host commands and a changed source invalidate an accepted intent.
 RTW88IEEE80211 pm;init(pm,hw,candidate,120000);receive(pm,candidate,120000);pm.btmTick(120001);reply=pm.submitted.back();
 pm.parent.allowed=false;pm.observeBtmTx(reply.data(),reply.size(),true);pm.btmTick(120020);assert(!pm._btmPhase&&!pm.joins);
 RTW88IEEE80211 manual;init(manual,hw,candidate,130000);receive(manual,candidate,130000);manual.btmTick(130001);reply=manual.submitted.back();
 manual.pauseAutoRoaming(130010);manual.observeBtmTx(reply.data(),reply.size(),true);manual.btmTick(130020);assert(!manual._btmPhase&&!manual.joins);
 RTW88IEEE80211 changed;init(changed,hw,candidate,140000);receive(changed,candidate,140000);changed.btmTick(140001);
 changed._targetBSS.bssid[5]^=1;changed.btmTick(140020);assert(!changed._btmPhase&&!changed.joins);
 // Never accept an incompatible RSN, even if the AP requests it.
 RTW88IEEE80211 security;init(security,hw,candidate,150000);candidate.ies[sizeof(ies)-2]=0x40;
 receive(security,candidate,150000);security.btmTick(150001);security.runManualScan();security.btmTick(150300);
 assert(!security._btmPhase&&!security.joins&&security.submitted.back()[27]==7);free(security._scanRequest);
 uint8_t out[11];assert(!RTW88Roaming::btmResponse(out,10,1,0,candidate.bssid));
 // Replayed manual-switch cooldown: preserve the exact reason after auto scans.
 RTW88IEEE80211 cool;init(cool,hw,candidate,200000);cool._roamSwitchLast=180000;
 receive(cool,candidate,200000);cool.btmTick(200001);
 assert(!cool._btmPhase&&!cool.joins&&cool._btmOutcome.reason==RTW88RoamSwitch::Cooldown);
 assert(cool._btmOutcome.cooldownMs==39999&&cool._btmOutcome.token==11);
 assert(!memcmp(cool._btmOutcome.target,candidate.bssid,6));
 cool.autoRoamTick(205000);
 assert(cool._btmOutcome.reason==RTW88RoamSwitch::Cooldown&&cool._btmOutcome.decisionMs==200001);
 assert(b._btmOutcome.ackMs==1020&&b._btmOutcome.switchMs==1020);
 assert(!RTW88Roaming::btmResponse(out,11,1,0,nullptr));
 RTW88Roaming::BtmRequest timed;timed.validity=255;timed.mode=4;timed.disassociationTimer=10;
 assert(RTW88Roaming::btmLifetimeMs(timed,100)==1024);
 puts("PASS: production BTM admission, accept/ACK/target binding, one-channel scan, security, deadlines, PM/manual/source cancellation and boot-disabled rejection");
}
'''
controller=(root/'src/kext/AirPortRTW.cpp').read_text()
callback=controller[controller.index('void AirPortRTW::btmTimerFired('):controller.index('void AirPortRTW::publishRoamDiagnostics(')]
assert callback.index('_diagnosticsInHardware,true')<callback.index('->btmTick(')<callback.index('_diagnosticsInHardware,false')
assert 'roamingActionsAllowed()' in callback and 'isPowered()' in callback
assert '_btmTimer->disable()' in controller and '_workLoop->removeEventSource(_btmTimer)' in controller
assert 'requestRoam(' not in method('void RTW88IEEE80211::queueBtm(')
schedule=controller[controller.index('bool AirPortRTW::scheduleBtmControl('):controller.index('void AirPortRTW::btmTimerFired(')]
timer_test=r'''
#include <cassert>
#include <cstdint>
struct OSObject{};
struct IOTimerEventSource{unsigned cancels=0,arms=0;bool *blockAfterArm=nullptr;
 void setTimeoutMS(unsigned){++arms;if(blockAfterArm)*blockAfterArm=false;}
 void cancelTimeout(){++cancels;}};
#define OSDynamicCast(type,obj) static_cast<type*>(obj)
uint64_t mach_absolute_time(){return 1000000;}
void absolutetime_to_nanoseconds(uint64_t t,uint64_t*n){*n=t;}
struct Backend{bool powered=true,pending=true;bool *fence=nullptr,*blockInTick=nullptr;unsigned ticks=0;
 bool isPowered(){return powered;}bool btmPending(){return pending;}unsigned btmPollMs(){return 20;}
 void btmTick(uint64_t){assert(fence&&*fence);++ticks;if(blockInTick)*blockInTick=false;}};
struct AirPortRTW:OSObject{bool _shutdown=false,allowed=true,_diagnosticsInHardware=false;unsigned samples=0;
 Backend *_ieee80211=nullptr;IOTimerEventSource *_btmTimer=nullptr;
 bool roamingActionsAllowed(){return allowed&&!_shutdown;}
 bool btmControlAvailable(){return _btmTimer&&roamingActionsAllowed();}
 bool scheduleBtmControl(unsigned);void publishRoamDiagnostics(){++samples;}
 static void btmTimerFired(OSObject*,IOTimerEventSource*);};
'''+schedule+callback+r'''
int main(){AirPortRTW a;Backend b;IOTimerEventSource t;a._ieee80211=&b;a._btmTimer=&t;b.fence=&a._diagnosticsInHardware;
 a.allowed=false;AirPortRTW::btmTimerFired(&a,&t);assert(!b.ticks&&!t.arms&&!a._diagnosticsInHardware);
 a.allowed=true;b.powered=false;AirPortRTW::btmTimerFired(&a,&t);assert(!b.ticks&&!t.arms);
 b.powered=true;AirPortRTW::btmTimerFired(&a,&t);assert(b.ticks==1&&t.arms==1&&!a._diagnosticsInHardware);
 b.blockInTick=&a.allowed;AirPortRTW::btmTimerFired(&a,&t);assert(b.ticks==2&&t.arms==1);
 a.allowed=true;t.blockAfterArm=&a.allowed;assert(!a.scheduleBtmControl(1)&&t.arms==2&&t.cancels>=3);
 a._shutdown=true;AirPortRTW::btmTimerFired(&a,&t);assert(b.ticks==2);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
 (p/'timer.cpp').write_text(timer_test)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined',str(p/'timer.cpp'),'-o',str(p/'timer')],check=True)
 subprocess.run([str(p/'timer')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
 print('PASS: production BTM timer PM fence, powered-only rearm, shutdown and late-arm cancellation')
