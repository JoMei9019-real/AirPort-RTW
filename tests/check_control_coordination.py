#!/usr/bin/env python3
"""Run real RRM and BTM together: one scanner, bounded wait, ACK and PM gates."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
fixture=(root/'tests/check_rrm.py').read_text()
ns={'__file__':str(root/'tests/check_rrm.py')}
exec(compile(fixture[:fixture.index("\ncases=r'''")],str(root/'tests/check_rrm.py'),'exec'),ns)
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
int main(){
 ieee80211_supported_band band;Wiphy w{{&band}};Ops ops;Hw hw{&w,&ops};
 RTW88BSS candidate;RTW88IEEE80211 b;b._hw=&hw;b._bssList=&candidate;
 b._roamingAssistEnabled=b._roamingCapsValid=b._autoRoamEnabled=b._stationBTM=true;
 b._rm.advertised=true;b.parent.btmAvailable=true;b._rssi=-65;
 uint8_t ies[]={70,5,2,0,0,0,0,48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
 memcpy(b._targetBSS.ies,ies,sizeof(ies));b._targetBSS.ies_len=sizeof(ies);
 memcpy(candidate.ies,ies,sizeof(ies));candidate.ies_len=sizeof(ies);candidate.observedMs=100200;candidate.rssi=-40;
 b._rm.clockTSF=10000000;b._rm.clockUs=100000000;
 uint8_t rm[]={5,0,7,0,0,38,16,19,0,5,115,36,0,0,100,0,0,255,255,255,255,255,255};
 std::vector<uint8_t> measurements(rm,rm+sizeof(rm));
 measurements.insert(measurements.end(),rm+5,rm+sizeof(rm));
 b.rrmReceive(measurements.data(),measurements.size(),100000);b.rrmTick(100001);
 assert(b._rm.phase==2&&b._rm.scanOwned);unsigned generation=b._scanGeneration;
 BtmRequest req;req.token=11;req.mode=1;req.validity=255;req.candidates.count=1;
 memcpy(req.candidates.entries[0].bssid,candidate.bssid,6);req.candidates.entries[0].channel=6;
 b.queueBtm(req,100002);
 assert(b._btmPhase==1&&b._rm.phase==2&&b._btmDeferred==1&&!b._rm.canceled);
 b.btmTick(100100);
 assert(!strcmp(b._btmStage,"waiting-radio-measurement")&&b._scanGeneration==generation&&b.submitted.empty());
 // A competing dialog is rejected without replacing the active request.
 auto other=req;other.token=12;b.queueBtm(other,100110);
 assert(b._btmRequest.token==11&&b._btmOutcome.token==11&&b._btmIngress.status==1);
 b.runManualScan();b.btmTick(100300);
 assert(b._rm.phase==1&&b._rm.refused==1&&b._btmPhase==1&&!b.joins);
 b.btmTick(100400);
 assert(!b._rm.phase&&b._btmPhase==2&&!b.joins&&b._scanGeneration==generation);
 auto reply=b.submitted.back();b.observeBtmTx(reply.data(),reply.size(),true);b.btmTick(100450);
 assert(b.joins==1&&b._btmOutcome.ackMs==100450);free(b._scanRequest);
 // Deadline and power fences always win over waiting for a busy radio.
 RTW88IEEE80211 busy;busy._targetBSS=b._targetBSS;busy._autoRoamEnabled=true;
 busy.parent.btmAvailable=true;busy.queueBtm(req,200000);busy._manualScanChannelCount=1;
 busy.btmTick(busy._btmDeadline-900);
 assert(!busy._btmPhase&&!busy.joins&&!strcmp(busy._btmOutcome.stage,"radio-busy-until-deadline"));
 busy._manualScanChannelCount=0;busy.queueBtm(req,300000);busy.parent.allowed=false;busy.btmTick(300100);
 assert(!busy._btmPhase&&!busy.joins&&!strcmp(busy._btmOutcome.stage,"link-or-power-changed"));
 puts("PASS: production combined RRM/BTM deferral, single scanner ownership, competing tokens, ACK-before-switch, deadline and PM fencing");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
