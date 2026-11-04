#!/usr/bin/env python3
"""Real SAE/EAPOL crypto and production scan completion; RF/OS calls are mocked."""
import os, shlex, subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
fixture_source = (root / 'tests/check_wpa3_hardware.py').read_text()
ns = {'__file__': str(root / 'tests/check_wpa3_hardware.py')}
exec(compile(fixture_source[:fixture_source.index('# Run the existing real SAE/AP exchange')],
             ns['__file__'], 'exec'), ns)
pre, methods, method = ns['pre'], ns['methods'], ns['method']
pre = pre.replace('struct Timer{void cancelTimeout(){}void wakeAtTime(uint64_t){}};',
                  'struct Timer{unsigned cancels=0,arms=0;void cancelTimeout(){++cancels;}void wakeAtTime(uint64_t){++arms;}};')
pre = pre.replace('void read_random(void*,unsigned){assert(false);}',
                  'void read_random(void*p,unsigned n){memset(p,0x44,n);}')
pre = pre.replace('bool _eapolTxProtect=false', 'bool failNextM4=false;bool _eapolTxProtect=false')
pre = pre.replace('delete p;return true;', 'delete p;if(failNextM4){failNextM4=false;return false;}return true;')
pre = pre.replace('struct Parent{unsigned ups=0;',
                  'struct Parent{unsigned resumes=0;void scanTxReady(){++resumes;}unsigned ups=0;')
pre = pre.replace('struct Delegate{void rtw88Event(unsigned,void*){}};',
                  'struct Delegate{bool deferWorkerEvent(unsigned,unsigned,unsigned){return false;}void rtw88Event(unsigned,void*){assert(false);}};')
pre = pre.replace('struct RTW88IEEE80211{', r'''
using RTW88State=unsigned;using UInt32=unsigned;
constexpr unsigned RTW88_STATE_IDLE=0,kRTW88EventScanDone=2;
struct RTW88BSS{RTW88BSS*next=nullptr;uint8_t bssid[6]={};unsigned last_seen_scan=0;};
void IOLockLock(void*){}void IOLockUnlock(void*){}
uint64_t mach_absolute_time(){return 1000000000ULL;}
void absolutetime_to_nanoseconds(uint64_t t,uint64_t*n){*n=t;}
struct RTW88IEEE80211{
 RTW88BSS *_bssList=nullptr;void *_bssLock=this;
 unsigned _scanGeneration=1,_bssCount=0,_lastScanCacheCount=0,homeRestores=0,psClears=0;
 bool _roamScanActive=false,_roamScanWorkerPending=false,_manualScanOnHomeChannel=false;
 bool _powered=true,_awdlReceiveMode=false;unsigned _awdlChannel=0;
 unsigned _roamScanResult=0,_manualScanChannelCount=0;uint64_t _roamScanCompletedMs=0;
 bool roamScanActive()const{return _roamScanActive;}
 void restoreConnectedChannel(){++homeRestores;}void txNullFunc(bool ps){assert(!ps);++psClears;}
 int setAWDLChannel(unsigned){return 0;}int setAWDLReceiveMode(bool){return 0;}
 void wakeTrace(const char*){}void resumeDeferredJoin(){}void scanDone(bool);
''')
pre = pre.replace('using IOReturn=int;', 'constexpr int kIOReturnSuccess=0;using IOReturn=int;')
methods += method('void RTW88IEEE80211::scanDone(')
pre += '\nvoid scanCases(const Session&,const std::vector<uint8_t>&);\n'
fixture = (root / 'tests/wpa3_session_test.cpp').read_text().replace('#include "../src/kext/RTW88WPA3.hpp"', '')
fixture = fixture.replace('m3[81]^=1;assert(', 'scanCases(s,m3);\n    m3[81]^=1;assert(', 1)
cases = r'''
void beginScan(RTW88IEEE80211&b){
 assert(b._state==RTW88_STATE_CONNECTED&&!b._roamScanActive&&!b._roamScanWorkerPending);
 b._state=RTW88_STATE_SCANNING;b._scanReturnState=RTW88_STATE_CONNECTED;
 b._roamScanActive=b._roamScanWorkerPending=true;b._roamScanResult=1;
 b._manualScanChannelCount=39;b._manualScanAbort=false;
}
void finishScan(RTW88IEEE80211&b,bool aborted){
 const auto restores=b.homeRestores,clears=b.psClears;
 b.scanDone(aborted);
 assert(b._state==RTW88_STATE_CONNECTED&&b._scanReturnState==RTW88_STATE_IDLE);
 assert(!b._roamScanActive&&b._roamScanResult==(aborted?3u:2u)&&b._roamScanCompletedMs==1000);
 assert(b.homeRestores==restores+1&&b.psClears==clears+1);
 // The real worker releases these only after scanDone returns.
 assert(b._roamScanWorkerPending);b._manualScanChannelCount=0;b._roamScanWorkerPending=false;
}
std::vector<uint8_t> groupKey(const Session&s,uint8_t replay,bool rotate=false){
 std::vector<uint8_t>kd(56);
 const uint8_t gtk[]={221,22,0,15,172,1,1,0},igtk[]={221,28,0,15,172,9,4,0};
 memcpy(kd.data(),gtk,8);memcpy(kd.data()+8,s.gtk[1],16);
 memcpy(kd.data()+24,igtk,8);memcpy(kd.data()+38,s.igtk[0],16);kd[54]=221;
 if(rotate){kd[8]^=replay;kd[38]^=replay;}
 std::vector<uint8_t>g1(163);g1[0]=2;g1[1]=3;g1[3]=159;g1[4]=2;g1[5]=0x13;g1[6]=0x80;g1[16]=replay;g1[98]=64;
 rtw_sae_aes_wrap(s.ptk+16,kd.data(),kd.size(),g1.data()+99);
 rtw_sae_aes_cmac(s.ptk,g1.data(),g1.size(),g1.data()+81);return g1;
}
void scanCases(const Session&prepared,const std::vector<uint8_t>&m3){
 for(bool software:{false,true}){
  RTW88IEEE80211 b;b._sae=prepared;b._saeSoftwareCCMP=software;b._state=RTW88_STATE_HANDSHAKING;
  memcpy(b._targetBSS.bssid,prepared.peer,6);b.wpa3Eapol(m3.data(),m3.size());
  assert(b._state==RTW88_STATE_CONNECTED&&b._sae.authorized&&b.parent.ups==1);
  beginScan(b);auto cancels=b.timer.cancels,arms=b.timer.arms,ups=b.parent.ups;
  // A valid duplicate M3 is answered, without ending a background scan.
  b.wpa3Eapol(m3.data(),m3.size());assert(b.m4==2);
  assert(b._state==RTW88_STATE_SCANNING&&b._roamScanActive&&b.timer.cancels==cancels&&b.timer.arms==arms&&b.parent.ups==ups);
  auto g1=groupKey(b._sae,3,true),bad=g1;bad[81]^=1;
  b.wpa3Eapol(bad.data(),bad.size());assert(b._sae.replay[7]==2);
  b.wpa3Eapol(g1.data(),g1.size());assert(b._sae.replay[7]==3);
  b._sae.rx[1][0]=42;b._sae.ipn[0]=10;
  b.wpa3Eapol(g1.data(),g1.size());assert(b._sae.rx[1][0]==42&&b._sae.ipn[0]==10);
  assert(b._state==RTW88_STATE_SCANNING&&b.timer.cancels==cancels&&b.timer.arms==arms&&b.parent.ups==ups);
  assert(b._sae.authorized&&!b._sae.pending&&!b._manualScanAbort);
  finishScan(b,false);
  // A fresh pairwise M1 asks the scanner to abort, without changing PTK,
  // replay/nonce state or the scan timer. Stale/truncated M1 cannot do so.
  beginScan(b);uint8_t m1[99]={2,3,0,95,2,0,0x88};m1[16]=2;memset(m1+17,0x66,32);
  b.wpa3Eapol(m1,sizeof(m1));assert(!b._manualScanAbort&&!b._sae.pending);
  m1[16]=4;b.wpa3Eapol(m1,98);assert(!b._manualScanAbort);
  uint8_t oldPTK[48];memcpy(oldPTK,b._sae.ptk,48);cancels=b.timer.cancels;arms=b.timer.arms;
  b.wpa3Eapol(m1,sizeof(m1));
  assert(b.scanAborts==1&&b._manualScanAbort&&b._state==RTW88_STATE_SCANNING);
  assert(!b._sae.pending&&b._sae.replay[7]==3&&!memcmp(oldPTK,b._sae.ptk,48));
  assert(b.timer.cancels==cancels&&b.timer.arms==arms);
  finishScan(b,true);
  // The AP's retry now starts and completes a real pairwise rekey.
  b.wpa3Eapol(m1,sizeof(m1));assert(b._state==RTW88_STATE_HANDSHAKING&&b._sae.pending&&b.timer.arms==arms+1);
  std::vector<uint8_t> next=m3,plain(m3.size()-99-8);next[16]=5;memcpy(next.data()+17,m1+17,32);
  assert(rtw_sae_aes_unwrap(prepared.ptk+16,m3.data()+99,m3.size()-99,plain.data()));
  rtw_sae_aes_wrap(b._sae.ptk+16,plain.data(),plain.size(),next.data()+99);
  memset(next.data()+81,0,16);rtw_sae_aes_cmac(b._sae.ptk,next.data(),next.size(),next.data()+81);
  b.failNextM4=true;b.wpa3Eapol(next.data(),next.size());
  assert(b._state==RTW88_STATE_HANDSHAKING&&!b._sae.pending&&b._sae.authorized&&b.parent.ups==ups);
  b.wpa3Eapol(next.data(),next.size());
  assert(b._state==RTW88_STATE_CONNECTED&&!b._sae.pending&&b._sae.authorized&&b.parent.ups==ups+1);
  assert(memcmp(oldPTK,b._sae.ptk,48)&&b.saeHardwareCCMP()==!software);
  cancels=b.timer.cancels;b.scanDone(false);assert(b.timer.cancels==cancels&&b._roamScanResult==3); // late completion
  for(unsigned i=0;i<16;++i){
   beginScan(b);cancels=b.timer.cancels;arms=b.timer.arms;ups=b.parent.ups;
   auto update=groupKey(b._sae,uint8_t(6+i),true);b.wpa3Eapol(update.data(),update.size());
   assert(b._sae.replay[7]==6+i&&b._state==RTW88_STATE_SCANNING&&b.timer.cancels==cancels&&b.timer.arms==arms&&b.parent.ups==ups);
   finishScan(b,i&1);
  }
  b.dispose();
 }
}
'''
host = (root / 'experimental/wpa3/test_host.py').read_text()
env = {'__file__': str(root / 'experimental/wpa3/test_host.py')}
exec(compile(host[:host.index('with tempfile.TemporaryDirectory(')], env['__file__'], 'exec'), env)
with tempfile.TemporaryDirectory() as tmp:
 p = Path(tmp); (p / 'test.cpp').write_text(pre + methods + fixture + cases)
 cc = shlex.split(os.environ.get('CC', 'cc')); cxx = shlex.split(os.environ.get('CXX', 'c++'))
 san = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']; objs = []
 for i, source in enumerate(env['sources']):
  obj = p / f'{i}.o'
  subprocess.run([*cc, *env['flags'], *san, '-c', str(source), '-o', str(obj)], check=True); objs.append(str(obj))
 obj = p / 'ccmp.o'
 subprocess.run([*cxx, '-std=c++17', '-O2', *san, '-c', str(root / 'src/kext/RTW88WPA3Crypto.cpp'), '-o', str(obj)], check=True); objs.append(str(obj))
 subprocess.run([*cxx, '-std=c++17', *san, '-g', '-I'+str(root/'src/kext'), '-I'+str(root/'tests'), str(p/'test.cpp'), *objs, '-o', str(p/'test')], check=True)
 subprocess.run([str(p / 'test')], check=True, timeout=60, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
print('PASS: real WPA3 GTK/IGTK and duplicate M3 preserve scan/timer, controlled pairwise-rekey abort/retry, actual home/PS/completion, repeated scans, HW/SW CCMP and late-completion guard')
