#!/usr/bin/env python3
"""Execute production Radio Measurement parsing, scanner and reply lifecycle.
RF measurement accuracy and FRITZ interoperability still require hardware.
"""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
fixture=(root/'tests/check_roam_diagnostics.py').read_text()
ns={'__file__':str(root/'tests/check_roam_diagnostics.py')}
exec(compile(fixture[:fixture.index("\ncases=r'''")],str(root/'tests/check_roam_diagnostics.py'),'exec'),ns)
pre,method,methods=ns['pre'],ns['method'],ns['methods']
pre=pre.replace('void rrmReceive(const uint8_t*,uint32_t,uint64_t){}',
                'void rrmReceive(const uint8_t*,uint32_t,uint64_t);')
pre=pre.replace('void rrmTick(uint64_t){}','void rrmTick(uint64_t);')
pre=pre.replace('void rrmCancel(const char*){_rm.phase=0;}',r'''
 void rrmCancel(const char*);
 bool rrmReply(const RTW88RRM::Request&,uint8_t,uint8_t);
 void rrmReport(const RTW88RRM::Request&,uint64_t);
''')
methods+=''.join(method(s) for s in ('void RTW88IEEE80211::rrmCancel(',
 'bool RTW88IEEE80211::rrmReply(', 'void RTW88IEEE80211::rrmReceive(',
 'void RTW88IEEE80211::rrmReport(', 'void RTW88IEEE80211::rrmTick('))
cases=r'''
uint8_t ies[]={70,5,2,0,0,0,0,48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
void init(RTW88IEEE80211&b,Hw&hw,RTW88BSS&candidate,uint64_t now){
 b._hw=&hw;b._bssList=&candidate;b._roamingAssistEnabled=b._roamingCapsValid=true;
 b._rm.advertised=true;b._rm.clockTSF=10000000;b._rm.clockUs=now*1000;
 b.parent.btmAvailable=true;
 memcpy(b._targetBSS.ies,ies,sizeof(ies));b._targetBSS.ies_len=sizeof(ies);
 auto&o=b._rm.cache[0].measurement;o={};o.seenMs=now;o.signal=-50;o.channel=36;o.phy=9;
 o.beacon=true;o.bodyLength=18;const uint8_t body[]={1,2,3,4,5,6,7,8,100,0,17,0,0,4,'T','e','s','t'};
 memcpy(o.body,body,sizeof(body));
 memcpy(b._rm.cache[0].bssid,candidate.bssid,6);memcpy(b._rm.cache[0].ssid,candidate.ssid,33);
 b._rm.cache[0].ssid_len=candidate.ssid_len;
}
std::vector<uint8_t> request(unsigned mode=2,unsigned channel=36,unsigned op=115){
 return {5,0,7,0,0,38,16,19,0,5,uint8_t(op),uint8_t(channel),0,0,100,0,uint8_t(mode),255,255,255,255,255,255};
}
void receive(RTW88IEEE80211&b,std::vector<uint8_t> p,uint64_t now){
 std::vector<uint8_t> f(24);f[0]=0xd0;memcpy(f.data()+4,b._macAddr,6);
 memcpy(f.data()+10,b._targetBSS.bssid,6);memcpy(f.data()+16,b._targetBSS.bssid,6);
 f.insert(f.end(),p.begin(),p.end());b.handleRoamingAction(f.data(),f.size(),now);
}
int main(){
 using namespace RTW88RRM;
 Requests parsed;auto req=request();assert(parse(req.data(),req.size(),parsed)&&parsed.count==1);
 for(size_t i=0;i<req.size();++i)assert(!parse(req.data(),i,parsed));
 auto malformed=req;malformed.push_back(0);assert(!parse(malformed.data(),malformed.size(),parsed));
 auto optional=req;optional.insert(optional.end(),{0,4,'T','e','s','t',2,1,1,10,1,0,164,1,1});optional[6]+=15;
 assert(parse(optional.data(),optional.size(),parsed)&&parsed.entries[0].detail==1&&parsed.entries[0].last);
 optional.back()=2;assert(!parse(optional.data(),optional.size(),parsed));
 auto multiple=req;multiple.insert(multiple.end(),req.begin()+5,req.end());
 assert(parse(multiple.data(),multiple.size(),parsed)&&parsed.count==2);
 for(int i=0;i<7;++i)multiple.insert(multiple.end(),req.begin()+5,req.end());
 assert(!parse(multiple.data(),multiple.size(),parsed));
 assert(channelInClass(121,116)&&!channelInClass(115,116)&&!channelInClass(0,36));
 ieee80211_supported_band band;Wiphy w{{&band}};Ops ops;Hw hw{&w,&ops};
 RTW88BSS candidate;RTW88IEEE80211 table;init(table,hw,candidate,1000);
 receive(table,req,1000);assert(table._rm.phase==1&&table.submitted.empty());
 table.rrmTick(1001);assert(table.submitted.size()==1&&!queued);
 auto f=table.submitted.back();assert(f[24]==5&&f[25]==1&&f[26]==7&&f[29]==19&&f[30]==0&&f[31]==5);
 assert(f[32]==115&&f[33]==36&&f[45]==120&&f[46]==255); // RCPI -50 dBm, RSNI unavailable
 for(unsigned i=34;i<44;++i)assert(!f[i]); // table start TSF/duration zero
 table.rrmTick(1002);assert(!table._rm.phase&&table._rm.reports==1);
 // Fresh scan generation only; passive on an ordinary channel never probes.
 RTW88IEEE80211 passive;init(passive,hw,candidate,100000);auto p=request(0);
 receive(passive,p,100000);passive.rrmTick(100001);
 assert(passive._rm.phase==2&&passive._rm.scanOwned&&passive._manualScanChannelCount==1);
 unsigned before=probes;passive.runManualScan();assert(probes==before&&!passive._rm.scanOwned);
 passive.rrmTick(100300);assert(passive._rm.empty==1); // stale table is not a measurement
 passive.rrmTick(100400);assert(!passive._rm.phase);free(passive._scanRequest);
 RTW88IEEE80211 active;init(active,hw,candidate,200000);
 receive(active,request(1),200000);active.rrmTick(200001);before=probes;
 active._rm.cache[0].measurement.generation=active._scanGeneration;active._rm.cache[0].measurement.startTSF=123456;
 active._rm.cache[0].measurement.durationTU=100;active._rm.cache[0].measurement.seenMs=200100;
 active.runManualScan();assert(probes==before+1);active.rrmTick(200300);
 assert(active._rm.reports==1&&!active._rm.empty);free(active._scanRequest);
 RTW88IEEE80211 dfs;init(dfs,hw,candidate,300000);
 receive(dfs,request(1,116,121),300000);dfs.rrmTick(300001);
 assert(dfs._rm.refused==1&&!dfs._rm.scans); // never probe DFS/no-IR
 RTW88IEEE80211 listen;init(listen,hw,candidate,400000);
 receive(listen,request(0,116,121),400000);listen.rrmTick(400001);before=probes;
 assert(listen._manualScanChannelCount==1);listen.runManualScan();assert(probes==before);
 listen.rrmTick(400300);free(listen._scanRequest);
 // Mandatory duration, repeated and unknown measurement types: explicit incapable.
 for(unsigned variant=0;variant<3;++variant){
  RTW88IEEE80211 reject;init(reject,hw,candidate,500000);auto q=req;
  if(variant==0)q[8]=16;else if(variant==1)q[3]=1;else q[9]=3;
  receive(reject,q,500000);reject.rrmTick(500001);
  assert(reject._rm.incapable==1&&reject.submitted.back()[30]==2&&!reject._rm.scans);
 }
 // Do not replace a pending dialog, and don't report after PM/source change.
 RTW88IEEE80211 busy;init(busy,hw,candidate,600000);receive(busy,req,600000);
 auto other=req;other[2]=8;receive(busy,other,600001);
 assert(busy._rm.busy==1&&busy._rm.requests.dialog==7&&busy.submitted.back()[26]==8);
 busy.parent.allowed=false;busy.rrmTick(600002);assert(!busy._rm.phase&&busy._rm.canceled==1);
 RTW88IEEE80211 missing;init(missing,hw,candidate,700000);missing._rm.clockTSF=0;
 receive(missing,request(0),700000);missing.rrmTick(700001);assert(missing._rm.refused&&!missing._rm.scans);
 RTW88IEEE80211 fail;init(fail,hw,candidate,800000);fail.txSucceeds=false;
 receive(fail,req,800000);fail.rrmTick(800001);assert(fail._rm.txFailed==1&&!fail._rm.reports);
 // Full frame body fragmentation and requested-IE filtering use production wire helper.
 Observation o=active._rm.cache[0].measurement;o.bodyLength=612;
 for(unsigned i=12;i<612;i+=6){o.body[i]=1;o.body[i+1]=4;memset(o.body+i+2,42,4);}
 Request r;r.mode=2;r.detail=2;r.last=true;r.token=19;size_t offset=0;unsigned fragments=0;uint8_t out[280];
 while(offset<o.bodyLength){auto n=report(out,sizeof(out),r,7,candidate.bssid,o,offset,1,fragments++,true);
  assert(n&&n<=260&&out[4]+5==n&&fragments<8);assert(out[n-1]==(offset==o.bodyLength));}
 assert(fragments>=3);
 uint32_t seed=1;uint8_t fuzz[1024];
 for(unsigned i=0;i<10000;++i){seed=seed*1664525+1013904223;size_t n=seed%1024;
  for(size_t j=0;j<n;++j){seed=seed*1664525+1013904223;fuzz[j]=uint8_t(seed>>24);}
  if(n>=5){fuzz[0]=5;fuzz[1]=0;}parse(fuzz,n,parsed);assert(parsed.count<=MaxRequests);}
 puts("PASS: production RRM malformed/fuzz parsing, table/active/passive reports, real scanner probe policy, DFS, fresh-generation isolation, fragmentation, busy/PM/clock/TX failure");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'rrm.cpp').write_text(pre+methods+cases)
 subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-fsanitize=address,undefined','-g','-I'+str(root/'src/kext'),str(p/'rrm.cpp'),'-o',str(p/'rrm')],check=True)
 subprocess.run([str(p/'rrm')],check=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
