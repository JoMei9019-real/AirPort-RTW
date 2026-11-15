#!/usr/bin/env python3
"""Execute native TX gating/restart and backend AWDL retune policy with OS/RF mocks."""
import os,re,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
controller=(root/'src/kext/AirPortRTW.cpp').read_text()
backend=(root/'src/kext/RTW88IEEE80211.cpp').read_text()
def method(source,signature):
 start=source.index(signature);end=source.index('{',start)+1;depth=1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]+'\n'
constants='\n'.join(re.findall(r'^static constexpr (?:unsigned int|UInt32) kRTW88Tx\w+\s*=\s*\d+;',controller,re.M))
pre=r'''
#include "RTW88Lifecycle.hpp"
#include "RTW88TxBatchScope.hpp"
#include <cassert>
#include <cstdio>
using UInt32=uint32_t;using IOOptionBits=unsigned;using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBusy=1,kIOReturnNotReady=2,kIOReturnUnsupported=3,kIOReturnNoResources=4;
constexpr int RTW88_STATE_IDLE=0,RTW88_STATE_CONNECTED=5;
constexpr int NL80211_NUM_BANDS=1,NL80211_CHAN_WIDTH_20_NOHT=0;
constexpr unsigned IEEE80211_CHAN_DISABLED=1,IEEE80211_CHAN_NO_IR=2,IEEE80211_CHAN_RADAR=4;
struct ieee80211_channel {unsigned hw_value=6,flags=0,band=0,center_freq=2437;};
struct ieee80211_supported_band {int n_channels=2,band=0;ieee80211_channel channels[2]={{6,0,0,2437},{36,4,0,5180}};};
struct Wiphy {ieee80211_supported_band *bands[1];};
struct Hw {Wiphy*wiphy;struct {struct {ieee80211_channel*chan;int width=0;unsigned center_freq1=0;} chandef;} conf;};
unsigned retunes=0;bool *ownership=nullptr;
void IOSleep(unsigned ms){assert(ms==6&&ownership&&*ownership);}
void rtw88_awdl_timeslice_switch_channel(Hw*){++retunes;}
void rtw88_awdl_switch_channel(Hw*){++retunes;}
struct RTW88IEEE80211 {
 bool _powered=true,_associatedVisible=true,_awdlOffChannel=false,_awdlHopsDisabled=false,scan=false,nullOK=true;
 unsigned _state=5,_btmPhase=0,_roamScanWorkerPending=0,_awdlChannel=0,_awdlPreparedChannel=0;
 uint32_t _awdlHopsBlocked=0,_awdlHopsPerformed=0;
 uint32_t _awdlHopPolicyChanges=0;bool _authenticationWorkerActive=false,restoreOK=true;
 struct Parent {bool allowed=true;unsigned resumes=0;bool roamingActionsAllowed(){return allowed;}void scanTxReady(){++resumes;}} parent;
 Parent*_parent=&parent;ieee80211_channel*home=nullptr;
 struct {unsigned phase=0;} _roamSwitch,_rm;
 struct {unsigned channel=116;} _targetBSS;
 Hw*_hw=nullptr;void*_vif=this;
 RTW88Lifecycle::Queue counters;
 bool isPowered(){return _powered;}
 bool staTxBlockedByAWDL(){return _awdlOffChannel;}
 bool staTxBlockedByScan(){return scan;}
 bool roamScanActive(){return scan;}
 bool txNullFunc(bool){return nullOK;}
 void restoreSTAChannelAfterAWDL(){_awdlOffChannel=false;if(restoreOK&&home)_hw->conf.chandef.chan=home;}
 void roamTrace(const char*){}
 bool beginTxBatch(){return true;}void endTxBatch(){}
 void recordTxEvent(unsigned i){++counters.events[i];}
 IOReturn setAWDLChannel(uint16_t);
 IOReturn configureAWDLHops(bool);
};
unsigned avail=255;unsigned rtw88_be_tx_avail(){return avail;}
bool preemption_enabled(){return true;}
struct IONetworkInterface {unsigned signals=0;void signalOutputThread(){++signals;}};
struct IOBasicOutputQueue {static constexpr int kServiceAsync=1;};
struct IOOutputQueue {unsigned size=0,services=0;unsigned getSize(){return size;}void service(int flag){assert(flag==1);++services;}};
struct Manager {bool suspended=false;bool powerSuspended(){return suspended;}};
struct IO80211Controller {unsigned pulls=0;IOReturn outputStart(IONetworkInterface*,IOOptionBits){++pulls;return 0;}};
#define super IO80211Controller
struct AirPortRTW:IO80211Controller {
 RTW88IEEE80211 *_ieee80211;Manager manager;Manager*_awdlManager=&manager;
 IONetworkInterface netif;IONetworkInterface *_netif=&netif;IOOutputQueue queue;
 bool _shutdown=false,_pmTransition=false,_dmaStopped=false,_txStalled=false,_txGated=false;
 uint32_t _txGateCount=0;
 IOOutputQueue*getOutputQueue(){return &queue;}void drainPendingFree(){}
 IOReturn outputStartBatched(IONetworkInterface*,IOOptionBits);
 bool txGateWanted();bool releaseTxStall();void kickGatedOutput();void resumeTxIfStalled();
};
'''
methods=method(backend,'IOReturn RTW88IEEE80211::setAWDLChannel(')+method(backend,'IOReturn RTW88IEEE80211::configureAWDLHops(')+''.join(method(controller,s) for s in (
 'IOReturn AirPortRTW::outputStartBatched(', 'bool AirPortRTW::txGateWanted(',
 'bool AirPortRTW::releaseTxStall(', 'void AirPortRTW::kickGatedOutput(',
 'void AirPortRTW::resumeTxIfStalled('))
cases=r'''
int main(){
 ieee80211_supported_band band;ieee80211_channel home{116,4,0,5580};Wiphy w{{&band}};Hw hw{&w,{{&home}}};
 RTW88IEEE80211 b;b._hw=&hw;ownership=&b._awdlOffChannel;
 b._awdlHopsDisabled=true;
 assert(b.setAWDLChannel(6)==kIOReturnBusy&&retunes==0&&!b._awdlOffChannel&&b._awdlHopsBlocked==1);
 b._state=RTW88_STATE_IDLE;assert(b.setAWDLChannel(6)==kIOReturnBusy&&retunes==0);
 b._state=5;b._awdlHopsDisabled=false;b.nullOK=false;
 assert(b.setAWDLChannel(6)==kIOReturnNotReady&&!b._awdlOffChannel&&!retunes);
 b.nullOK=true;assert(b.setAWDLChannel(6)==0&&b._awdlOffChannel&&retunes==1&&b._awdlHopsPerformed==1);
 b._awdlHopsDisabled=true;assert(b.setAWDLChannel(6)==0&&retunes==1); // same-channel use
 b._awdlOffChannel=false;b._hw->conf.chandef.chan=&home;b._awdlHopsDisabled=false;
 assert(b.setAWDLChannel(36)==kIOReturnUnsupported&&retunes==1); // no DFS bypass
 b.scan=true;assert(b.setAWDLChannel(6)==kIOReturnBusy&&retunes==1);b.scan=false;
 b._powered=false;assert(b.setAWDLChannel(6)==kIOReturnNotReady&&retunes==1);b._powered=true;
 b.home=&home;b._hw->conf.chandef.chan=&band.channels[0];b._awdlOffChannel=true;
 assert(b.configureAWDLHops(true)==0&&b._awdlHopsDisabled&&!b._awdlOffChannel&&b._hw->conf.chandef.chan==&home);
 assert(b.parent.resumes==1&&b._awdlHopPolicyChanges==1&&b.setAWDLChannel(6)==kIOReturnBusy);
 assert(b.configureAWDLHops(false)==0&&!b._awdlHopsDisabled&&b._awdlHopPolicyChanges==2);
 b.scan=true;assert(b.configureAWDLHops(true)==kIOReturnBusy&&!b._awdlHopsDisabled);b.scan=false;
 b.parent.allowed=false;assert(b.configureAWDLHops(true)==kIOReturnNotReady&&!b._awdlHopsDisabled);b.parent.allowed=true;
 b._hw->conf.chandef.chan=&band.channels[0];b._awdlOffChannel=true;b.restoreOK=false;
 assert(b.configureAWDLHops(true)==kIOReturnNotReady&&b._awdlOffChannel&&b.parent.resumes==1);
 b.restoreOK=true;assert(b.configureAWDLHops(true)==0&&!b._awdlOffChannel&&b.parent.resumes==2);
 assert(b.configureAWDLHops(false)==0&&!b._awdlHopsDisabled);
 AirPortRTW a;a._ieee80211=&b;b._awdlOffChannel=true;
 assert(a.outputStartBatched(a._netif,0)==kIOReturnNoResources&&a.pulls==0&&a._txGated);
 a._txStalled=true;a.resumeTxIfStalled();assert(a.queue.services==0&&a.netif.signals==0);
 b._awdlOffChannel=false;a.resumeTxIfStalled();
 assert(a.queue.services==1&&a.netif.signals==1&&!a._txStalled&&!a._txGated);
 assert(a.outputStartBatched(a._netif,0)==0&&a.pulls==1);
 a.queue.size=128;assert(a.outputStartBatched(a._netif,0)==kIOReturnNoResources&&a.pulls==1);
 a.queue.size=65;a.kickGatedOutput();assert(a.netif.signals==1);
 a.queue.size=64;a.kickGatedOutput();assert(a.netif.signals==2);
 avail=95;assert(a.outputStartBatched(a._netif,0)==kIOReturnNoResources&&a.pulls==1);
 a._txStalled=true;avail=159;a.resumeTxIfStalled();assert(a._txStalled);
 avail=160;a._pmTransition=true;a.resumeTxIfStalled();assert(a._txStalled);
 a._pmTransition=false;a.manager.suspended=true;a.resumeTxIfStalled();assert(a._txStalled);
 a.manager.suspended=false;a.resumeTxIfStalled();assert(!a._txStalled);
 assert(b.counters.events[RTW88Lifecycle::GateAWDLChecks]>=1&&b.counters.events[RTW88Lifecycle::QueueResumes]==2);
 puts("PASS: production AWDL early gate, retained backlog, asynchronous home/reclaim resume, hysteresis, PM fence and boot retune policy");
}
'''
assert controller.index('setAWDLHopsDisabled(hopsDisabled)')<controller.index('_ieee80211->start()')
control=method(controller,'IOReturn AirPortRTW::setProperties(')
branch=control[control.index('} else if(request->operation==11'):control.index('} else if(request->operation!=5)')]
assert branch.index('_diagnosticsInHardware,true')<branch.index('->configureAWDLHops(')<branch.index('_diagnosticsInHardware,false')
assert 'pauseAutoRoaming' not in branch and 'IOSleep' not in branch
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+constants+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
