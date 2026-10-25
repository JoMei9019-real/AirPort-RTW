#!/usr/bin/env python3
"""Execute production wake tracing and retained queue diagnostics with mocked time."""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
fixture=(root/'tests/check_roam_diagnostics.py').read_text()
ns={'__file__':str(root/'tests/check_roam_diagnostics.py')}
exec(compile(fixture[:fixture.index("\ncases=r'''")],str(root/'tests/check_roam_diagnostics.py'),'exec'),ns)
pre=ns['pre'].replace('void wakeTrace(const char*){}','void wakeTrace(const char*);void beginWakeTrace();')
method=ns['method']
methods=ns['methods']+method('void RTW88IEEE80211::beginWakeTrace(')+method('void RTW88IEEE80211::wakeTrace(')
cases=r'''
int main(){
 RTW88IEEE80211 b;
 ticks=1000000000;b.beginWakeTrace();
 ticks=1100000000;b.wakeTrace("radio-ready");
 ticks=1500000000;b.wakeTrace("scan-start");
 ticks=2200000000;b.wakeTrace("scan-done");
 ticks=2300000000;b.roamTrace("auth-worker-start");
 ticks=2400000000;b.roamTrace("auth-response-ok");
 ticks=2500000000;b.roamTrace("assoc-response-ok");
 ticks=2700000000;b.roamTrace("data-keys-installed");
 ticks=2800000000;b.wakeTrace("first-data");
 assert(!b._wakeTrace.active&&b._wakeTrace.points[RTW88Lifecycle::Keys]==2700);
 uint8_t original[6];memcpy(original,b._wakeTrace.firstAP,6);
 b._targetBSS.bssid[5]^=1;ticks=9000000000;
 b.roamTrace("data-keys-installed");b.wakeTrace("first-data");
 assert(b._wakeTrace.points[RTW88Lifecycle::Keys]==2700&&!memcmp(original,b._wakeTrace.firstAP,6));
 b._queueTrace.sample(3000,10,20,0,5);b._queueTrace.sample(8000,14,27,2,1);
 assert(b._queueTrace.dropDelta==4&&b._queueTrace.stallDelta==7&&b._queueTrace.state==1);
 char out[32768];b.copyRoamDiagnostics(out,sizeof(out),9000);
 assert(strstr(out,"wake_keys_ms=1700\n")&&strstr(out,"wake_data_ms=1800\n"));
 assert(strstr(out,"queue_drop_delta=4\n"));
 b._queueTrace.sample(9000,1,2,0,5);assert(!b._queueTrace.dropDelta&&!b._queueTrace.stallDelta);
 b._autoRoamEnabled=b._roamingAssistEnabled=b._roamSwitchEnabled=true;b._autoNextMs=20000;b._autoStage="neighbor-response-pending";
 b.autoRoamTick(9000);assert(!strcmp(b._autoStage,"waiting-next-scan"));
 b.beginWakeTrace();assert(b._wakeTrace.generation==2&&!b._wakeTrace.points[RTW88Lifecycle::Keys]);
 puts("PASS: production wake milestones survive later roaming, bounded snapshots, counter reset/deltas and transient status");
}
'''
controller=(root/'src/kext/AirPortRTW.cpp').read_text()
resume=controller[controller.index('void AirPortRTW::resumeTxIfStalled()'):controller.index('void AirPortRTW::drainPendingFree()')]
assert resume.index('_pmTransition')<resume.index('releaseTxStall();')
assert 'kServiceAsync' in resume and 'staTxBlockedByScan()' in resume
assert 'resumeTxIfStalled();' in resume[resume.index('void AirPortRTW::scanTxReady()'):]
scan=method('void RTW88IEEE80211::runManualScan(')
assert scan.index('_manualScanOnHomeChannel = true;')<scan.index('->scanTxReady()')
assert '->scanTxReady()' in method('void RTW88IEEE80211::scanDone(')
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'},timeout=30)
