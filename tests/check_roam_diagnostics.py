#!/usr/bin/env python3
"""Run production refresh, diagnostics and single-channel scanner with RF/OS mocks."""
import os, re, subprocess, tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
fixture=(root/'tests/check_roam_switch.py').read_text()
ns={'__file__':str(root/'tests/check_roam_switch.py')}
exec(compile(fixture[:fixture.index("cases=r'''")],str(root/'tests/check_roam_switch.py'),'exec'),ns)
pre,method=ns['pre'],ns['method']
pre=pre.replace('template<class... T> void IOLog(const char *, T...) {}',r'''
#include <cstdarg>
#include <cstdlib>
#include <string>
std::string logs;
void IOLog(const char *fmt,...) { char out[1024];va_list a;va_start(a,fmt);vsnprintf(out,sizeof(out),fmt,a);va_end(a);logs+=out; }
uint64_t ticks=1000000000;uint64_t mach_absolute_time(){return ticks;}
void absolutetime_to_nanoseconds(uint64_t t,uint64_t *n){*n=t;}
''')
pre=pre.replace('int hw_value=6,center_freq=2437,flags=0;', 'int hw_value=6,center_freq=2437,flags=0,band=0;')
pre=pre.replace('int n_channels=1;Channel channels[1];','int n_channels=4,band=0;Channel channels[4]={{6,2437,0,0},{11,2462,1,0},{36,5180,0,1},{116,5580,6,1}};')
pre=pre.replace('struct Hw{Wiphy*wiphy;struct {struct {Channel *chan=nullptr;} chandef;} conf;};',r'''
struct ieee80211_scan_request {struct {Channel **channels=nullptr;int n_channels=0;} req;};
struct Hw;
struct Ops {int (*hw_scan)(Hw*,void*,ieee80211_scan_request*)=nullptr;};
struct Hw {Wiphy*wiphy;Ops *ops=nullptr;struct {struct {Channel *chan=nullptr;int width=0,center_freq1=0;} chandef;} conf;};
unsigned queued=0,probes=0,switches=0,restores=0;std::vector<bool> ps;
constexpr int NL80211_BAND_2GHZ=0,NL80211_BAND_5GHZ=1,NL80211_CHAN_WIDTH_20_NOHT=0,kMillisecondScale=1,kIOReturnNoMemory=7;
void *IOMallocZero(size_t n){return calloc(1,n);}
bool rtw88_hw_scan_supported(Hw*){return true;}
void thread_call_enter(void*){++queued;}
void clock_interval_to_deadline(unsigned n,int,uint64_t *d){*d=n;}
void IOSleep(unsigned){}
void rtw88_sw_scan_start(Hw*,void*){}
void rtw88_sw_scan_switch_channel(Hw *h){assert(h->conf.chandef.chan->hw_value!=11);++switches;}
void rtw88_sw_scan_complete(Hw*,void*){}
struct Timer {void wakeAtTime(uint64_t){}};
''')
pre=pre.replace('void roamTrace(const char*,uint32_t=0){}',r'''
 const char *_roamStage="idle";uint64_t _roamStageMs=0,_roamScanCompletedMs=0;uint32_t _roamDataRx=0;
 void roamTrace(const char*,uint32_t=0);
 unsigned roamingStat(unsigned i)const{return _roamingStats[i];}
 unsigned roamSwitchResult()const{return _roamSwitchResult;}
 void copyRoamDiagnostics(char*,uint32_t,uint64_t)const;
 IOReturn refreshRoamNeighbors(uint64_t);IOReturn scanRoamTarget(const uint8_t*,uint64_t);
 IOReturn startRoamScan(uint16_t,uint64_t);IOReturn discoverRoamAPs(uint64_t);IOReturn selectRoamTarget(uint64_t);
 IOReturn cmdScan(uint16_t=0);void runManualScan();
 void autoRoamTick(uint64_t);
 void pauseAutoRoaming(uint64_t now){cancelBTM("manual-command");_autoScanPending=false;_autoNextMs=now+60000;}
 int _rssi=-45;uint32_t _scanGeneration=0,_lastScanCacheCount=0,_lastScanChannelCount=0;
 uint32_t _scanVisited2GHz=0,_scanVisited5GHz=0,_timeoutMs=0,_rxFrameCount=0;
 int _scanReturnState=0,_awdlPreparedChannel=0;const char *_scanEngine="none";
 bool _manualScanAbort=false,_manualScanOnHomeChannel=false,_manualScanFallbackLogged=false;
 ieee80211_scan_request *_scanRequest=nullptr;Channel *_scanRequestChannels[256]={},*_manualScanChannels[256]={};
 void *_manualScanTC=this,*_vif=this;Timer timer;Timer *_timer=&timer;
 void restoreConnectedChannel(){++restores;}void txNullFunc(bool x){ps.push_back(x);}void txProbeRequest(){assert(!(_hw->conf.chandef.chan->flags&6));++probes;}
 void scanDone(bool aborted){assert(_scanReturnState==5);restoreConnectedChannel();txNullFunc(false);_state=5;_scanReturnState=0;_roamScanResult=aborted?3:2;_roamScanActive=false;}
''')
# Real scanner uses RTW88State only as a state-value type.
pre=pre.replace('using IOReturn=int;', 'using IOReturn=int;using RTW88State=int;')
pre=pre.replace('uint64_t observedMs=1000,', 'uint32_t last_seen_scan=0;uint64_t observedMs=1000,')
pre=pre.replace('uint8_t ssid_len=4;', 'uint8_t ssid_len=4,channel=6;')
pre=re.sub(r'\bChannel\b','ieee80211_channel',pre)
pre=re.sub(r'\bBand\b','ieee80211_supported_band',pre)
methods=ns['methods']+''.join(method(x) for x in (
 'void RTW88IEEE80211::roamTrace(', 'bool RTW88IEEE80211::sendRoamingAction(',
 'void RTW88IEEE80211::roamingTick(', 'void RTW88IEEE80211::handleRoamingAction(',
 'IOReturn RTW88IEEE80211::refreshRoamNeighbors(', 'IOReturn RTW88IEEE80211::scanRoamTarget(',
 'IOReturn RTW88IEEE80211::startRoamScan(', 'IOReturn RTW88IEEE80211::discoverRoamAPs(',
 'IOReturn RTW88IEEE80211::selectRoamTarget(',
 'void RTW88IEEE80211::autoRoamTick(',
 'IOReturn RTW88IEEE80211::cmdScan(', 'void RTW88IEEE80211::runManualScan(',
 'void RTW88IEEE80211::copyRoamDiagnostics('))
cases=r'''
int main() {
 using namespace RTW88RoamSwitch;
 RTW88IEEE80211 b;ieee80211_supported_band band;Wiphy w{{&band}};Ops ops;Hw hw{&w,&ops};RTW88BSS candidate;
 b._hw=&hw;b._bssList=&candidate;b._roamingAssistEnabled=true;b._roamingCapsValid=true;
 uint8_t ies[]={70,5,2,0,0,0,0,48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
 memcpy(b._targetBSS.ies,ies,sizeof(ies));b._targetBSS.ies_len=sizeof(ies);
 memcpy(candidate.ies,ies,sizeof(ies));candidate.ies_len=sizeof(ies);
 assert(b.refreshRoamNeighbors(1000)==0&&b._roaming.pending&&b.submitted.size()==1);
 assert(b.refreshRoamNeighbors(1001)==kIOReturnBusy&&b._roamReason==RefreshPending);
 auto response=std::vector<uint8_t>(24);response[0]=0xd0;
 memcpy(response.data()+4,b._macAddr,6);memcpy(response.data()+10,b._targetBSS.bssid,6);memcpy(response.data()+16,b._targetBSS.bssid,6);
 response.insert(response.end(),{5,5,b._roaming.pendingToken,52,13,2,9,8,7,6,1,0,0,0,0,81,6,7});
 b.handleRoamingAction(response.data(),response.size(),1100);assert(b._roamLastResponseCount==1);
 assert(b.refreshRoamNeighbors(2000)==kIOReturnBusy&&b._roamReason==RefreshLimited);
 b.roamingTick(32000);assert(!b._roaming.neighbors.count&&b._roamLastResponseCount==1);
 assert(b.checkRoam(candidate.bssid,32000)==kIOReturnNotFound&&b._roamReason==ScanStale);
 assert(b.refreshRoamNeighbors(32001)==0&&b._roaming.pending); // no Wi-Fi toggle
 response[26]=b._roaming.pendingToken;b.handleRoamingAction(response.data(),response.size(),32002);
 candidate.observedMs=1;
 assert(b.checkRoam(candidate.bssid,32003)==kIOReturnNotFound&&b._roamReason==ScanStale);
 band.channels[0].flags=IEEE80211_CHAN_RADAR|IEEE80211_CHAN_NO_IR;
 candidate.observedMs=32002;
 assert(b.checkRoam(candidate.bssid,32004)==kIOReturnNotFound&&b._roamReason==BeaconMissing&&!queued);
 candidate.beaconObservedMs=32002;assert(b.checkRoam(candidate.bssid,32004)==0);
 band.channels[0].flags=IEEE80211_CHAN_DISABLED;
 assert(b.scanRoamTarget(candidate.bssid,32004)==kIOReturnNotFound&&b._roamReason==ChannelDisabled&&!queued);
 band.channels[0].flags=0;
 assert(b.cmdScan()==kIOReturnBusy&&!queued); // ordinary connected scans still prohibited
 assert(b.scanRoamTarget(candidate.bssid,32005)==0&&b.roamScanActive()&&queued==1);
 assert(b._manualScanChannelCount==1&&b._manualScanChannels[0]->hw_value==6);
 b.runManualScan();assert(!b.roamScanActive()&&b._state==5&&switches==1&&probes==1&&restores>=2);
 assert(ps.size()>=3&&ps.front()&& !ps.back()); // PS set off-channel, restored on home channel
 assert(b._lastScanChannelCount==1&&!b._manualScanChannelCount);
 candidate.observedMs=32006;assert(b.checkRoam(candidate.bssid,32007)==0&&!b.disconnects);
 candidate.ssid[0]='X';assert(b.checkRoam(candidate.bssid,32007)==kIOReturnNotFound&&b._roamReason==SSIDMismatch);candidate.ssid[0]='T';
 candidate.rssi=-90;assert(b.checkRoam(candidate.bssid,32007)==kIOReturnNotFound&&b._roamReason==SignalWeak);candidate.rssi=-45;
 b._bssList=nullptr;assert(b.checkRoam(candidate.bssid,32007)==kIOReturnNotFound&&b._roamReason==ScanMissing);b._bssList=&candidate;
 assert(b.scanRoamTarget(candidate.bssid,32008)==kIOReturnBusy&&b._roamReason==ScanLimited);
 b.parent.allowed=false;assert(b.checkRoam(candidate.bssid,32009)==kIOReturnNotReady&&b._roamReason==PowerBlocked);
 b.parent.allowed=true;
 char out[8192];b.copyRoamDiagnostics(out,sizeof(out),32010);
 assert(strstr(out,"last_response_count=1")&&strstr(out,"checked_scan_age_ms=")&&strstr(out,"reason=power-transition-or-off"));
 char tiny[8];memset(tiny,'X',sizeof(tiny));b.copyRoamDiagnostics(tiny,sizeof(tiny),32010);assert(!tiny[7]);
 b._roamLogLevel=0;auto before=logs.size();b.roamTrace("suppressed");assert(logs.size()==before&&!strcmp(b._roamStage,"suppressed"));
 b._roamLogLevel=2;b.roamTrace("diagnostic-test",123);
 assert(logs.find("stage=diagnostic-test detail=123")!=std::string::npos);
 assert(!strstr(out,"pmk=")&&!strstr(out,"password=")&&!strstr(out,"nonce="));
 assert(b.scanRoamTarget(candidate.bssid,38000)==0&&b._roamScanWorkerPending);
 b._manualScanAbort=true;b.runManualScan();
 assert(!b._roamScanWorkerPending&&!b.roamScanActive()&&b._roamScanResult==3&&switches==1&&b._state==5);
 // Real discovery plan skips disabled channels, listens on DFS without probes,
 // and restores the home channel between slots. No Neighbor Report required.
 b._roaming.neighbors={};b._roaming.neighborsMs=0;
 unsigned beforeProbes=probes,beforeSwitches=switches;
 assert(b.discoverRoamAPs(50000)==0&&b._manualScanChannelCount==3);
 b.runManualScan();assert(switches-beforeSwitches==3&&probes-beforeProbes==2&&!b._roamScanWorkerPending);
 assert(b._state==5&&band.channels[3].flags==6&&band.channels[1].flags==1);
 candidate.observedMs=50000;assert(b.checkRoam(candidate.bssid,50001)==0&&b._roamTargetFromScan);
 RTW88BSS five=candidate;five.bssid[5]=99;five.channel=36;five.freq=5180;five.rssi=-65;
 candidate.next=&five;b._rssi=-45;b._targetBSS.channel=6;
 assert(b.selectRoamTarget(50002)==0&&!memcmp(b._roamRecommended,five.bssid,6));
 five.rssi=-74;assert(b.selectRoamTarget(50003)==0&&!memcmp(b._roamRecommended,b._targetBSS.bssid,6));
 b._targetBSS.channel=36;b._rssi=-75;
 assert(b.selectRoamTarget(50004)==0&&!memcmp(b._roamRecommended,b._targetBSS.bssid,6));
 b._rssi=-79;assert(b.selectRoamTarget(50005)==0&&!memcmp(b._roamRecommended,candidate.bssid,6));
 b._rssi=-65;five.rssi=-62;assert(b.selectRoamTarget(50006)==0&&b._roamReason==KeepCurrent);
 five.rssi=-58;assert(b.selectRoamTarget(50007)==0&&!memcmp(b._roamRecommended,five.bssid,6));
 five.channel=116;five.freq=5580;five.beaconObservedMs=0;
 assert(b.checkRoam(five.bssid,50008)==kIOReturnNotFound&&b._roamReason==BeaconMissing);
 five.beaconObservedMs=50000;assert(b.checkRoam(five.bssid,50009)==0);
 five.capabilities=0x12;assert(b.checkRoam(five.bssid,50010)==kIOReturnNotFound&&b._roamReason==BeaconMissing);five.capabilities=0x11;
 assert(b.checkRoam(five.bssid,80000)==kIOReturnNotFound&&b._roamReason==ScanStale);
 uint8_t ap[]={2,3,4,5,6,7};
 assert(beaconProof(0x80,0,0x11,116,5580,true,ap,ap));
 assert(!beaconProof(0x50,0,0x11,116,5580,true,ap,ap));
 assert(!beaconProof(0x80,1,0x11,116,5580,true,ap,ap));
 assert(!beaconProof(0x80,0,0x12,116,5580,true,ap,ap));
 assert(!beaconProof(0x80,0,0x11,116,5500,true,ap,ap));
 assert(!beaconProof(0x80,0,0x11,116,5580,false,ap,ap));
 assert(!beaconProof(0x4080,0,0x11,116,5580,true,ap,ap));
 b.copyRoamDiagnostics(out,sizeof(out),50010);assert(strstr(out,"ap[0]=")&&strstr(out,"recommended_bssid="));
 free(b._scanRequest);
 // Production automatic scheduler: no scan during warmup/cooldown, bounded
 // discovery, stronger 5 GHz selection, manual precedence and PM cancellation.
 RTW88IEEE80211 a;RTW88BSS near=candidate;near.next=nullptr;
 near.channel=36;near.freq=5180;near.rssi=-45;near.observedMs=130000;
 a._hw=&hw;a._bssList=&near;a._roamingAssistEnabled=true;a._roamingCapsValid=true;a._autoRoamEnabled=true;
 memcpy(a._targetBSS.ies,ies,sizeof(ies));a._targetBSS.ies_len=sizeof(ies);
 a._targetBSS.channel=6;a._rssi=-60;
 a.autoRoamTick(100000);assert(a._autoNextMs==130000&&!a._autoScanPending);
 a.autoRoamTick(129999);assert(!a._autoScanPending);
 a.autoRoamTick(130000);assert(a._autoScanPending&&a._autoScans==1&&a._state==1);
 a.autoRoamTick(130001);assert(a._autoScans==1&&!a.joins);
 a.runManualScan();a.autoRoamTick(140000);
 assert(a._autoSwitches==1&&a.joins==1&&a._roamSwitch.phase==1);
 a.autoRoamTick(145000);assert(a.joins==1);
 a._roamSwitch.clear();a._state=5;a._associatedVisible=true;a._ptkConf=a._gtkConf=&a;
 a._roamingCapsValid=true; // Real diagnostics calls roamingTick before autoRoamTick.
 a._autoNextMs=150000;a.autoRoamTick(150000);assert(a._autoScans==1); // cooldown
 a._roamSwitchLast=0;a.pauseAutoRoaming(200000);
 a.autoRoamTick(259999);assert(a._autoScans==1);
 a.autoRoamTick(260000);assert(a._autoScanPending&&a._autoScans==2);
 a.pauseAutoRoaming(260001);a.runManualScan();a.autoRoamTick(270000);
 assert(a.joins==1&&!a._autoScanPending); // manual request owns completed scan
 a._autoNextMs=280000;a.autoRoamTick(280000);assert(a._autoScanPending);
 a.parent.allowed=false;a.autoRoamTick(280001);assert(!a._autoScanPending);
 a._manualScanAbort=true;a.runManualScan();a.parent.allowed=true;
 a._autoRoamEnabled=false;a.autoRoamTick(400000);assert(a._autoScans==3&&!a._autoScanPending);
 a._autoRoamEnabled=true;a._autoNextMs=500000;a.autoRoamTick(500000);
 assert(a._autoScanPending);a._manualScanAbort=true;a.runManualScan();a.autoRoamTick(510000);
 assert(!strcmp(a._autoStage,"scan-aborted-or-replaced")&&a.joins==1);
 a._autoNextMs=520000;near.observedMs=520000;a.autoRoamTick(520000);a.runManualScan();a.autoRoamTick(525000);
 assert(!strcmp(a._autoStage,"current-ap-preferred")&&a.joins==1);
 free(a._scanRequest);
 puts("PASS: refresh/scan diagnostics, no-neighbor RF targets, bounded discovery, passive DFS/beacon guards, disabled channels, 5 GHz priority/hysteresis, fallback and snapshots");
}
'''
controller=(root/'src/kext/AirPortRTW.cpp').read_text()
control=controller[controller.index('IOReturn AirPortRTW::setProperties('):controller.index('void AirPortRTW::waitForDiagnosticsIdle()')]
assert control.index('clientHasPrivilege(')<control.index('_workLoop->runAction(')
scoped=control[control.index('} else if(request->operation!=5)'):]
assert scoped.index('_diagnosticsInHardware,true')<scoped.index('->scanRoamTarget(')<scoped.index('_diagnosticsInHardware,false')
assert 'IOSleep(' not in control and 'thread_call_cancel_wait' not in control
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
