#!/usr/bin/env python3
"""Known panic-path containment: execute the production outer IOCTL prefix.
No Apple binary is emulated; this does not reproduce/fix its canary overwrite.
"""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'src/kext/AirPortRTW.cpp').read_text()
a=s.index('SInt32 AirPortRTW::apple80211_ioctl(IO80211Interface *interface,')
e=s.index('    /* Ventura is the native ABI for this kext. */',a)
prefix=s[a:e]
assert 'super::apple80211_ioctl' not in prefix
assert 'RTW88IOCTLGuard::legacyErrorQuery' in prefix
# All old/new host and virtual-interface superclass routes occur after this.
outer=s[a:s.index('\nnamespace {',e)]
assert outer.index('legacyErrorQuery')<outer.index('version_major < 23')<outer.index('super::apple80211_ioctl')
pre=r'''
#include "RTW88IOCTLGuard.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
using SInt32=int;using ifnet_t=void*;
constexpr unsigned SIOCGA80211=1,SIOCSA80211=2,APPLE80211_IOC_ERROR_STRING=209,APPLE80211_IOC_ERROR_NO=210;
constexpr bool kOSBooleanTrue=true;
struct IO80211Interface{};struct IO80211VirtualInterface{};
struct apple80211req{char name[16]={};uint32_t req_type=0,req_val=0,req_len=0;void*req_data=nullptr;};
struct AirPortRTW{
 unsigned forwards=0,properties=0;
 template<class...T>void setProperty(T...){++properties;}
 SInt32 apple80211_ioctl(IO80211Interface*,IO80211VirtualInterface*,ifnet_t,unsigned long,void*);
};
'''
# Stop exactly where the actual legacy delegation would begin, replacing
# only the (unavailable) superclass with an observable forwarding counter.
body=prefix+'    ++forwards;return 17;\n}\n'
cases=r'''
int main(){
 for(unsigned selector=0;selector<1024;++selector)
  assert(RTW88IOCTLGuard::legacyErrorQuery(selector)==(selector==209||selector==210));
 for(bool virt:{false,true})for(unsigned selector:{209u,210u})for(unsigned len:{0u,1u,8u,256u,0xffffffffu}){
  AirPortRTW c;struct{uint64_t before=0x12345678;apple80211req req;uint64_t after=0xabcdef;}g;
  g.req.req_type=selector;g.req.req_len=len;g.req.req_data=reinterpret_cast<void*>(1); // deliberately unusable userspace payload
  IO80211Interface iface;IO80211VirtualInterface vif;
  assert(c.apple80211_ioctl(&iface,virt?&vif:nullptr,nullptr,SIOCGA80211,&g.req)==102);
  assert(c.forwards==0&&c.properties==2&&g.before==0x12345678&&g.after==0xabcdef);
  assert(g.req.req_type==selector&&g.req.req_len==len&&g.req.req_data==reinterpret_cast<void*>(1));
  assert(c.apple80211_ioctl(&iface,virt?&vif:nullptr,nullptr,SIOCSA80211,&g.req)==17&&c.forwards==1);
 }
 AirPortRTW c;apple80211req q;q.req_type=208;
 assert(c.apple80211_ioctl(nullptr,nullptr,nullptr,SIOCGA80211,&q)==17&&c.forwards==1);
 assert(c.apple80211_ioctl(nullptr,nullptr,nullptr,SIOCGA80211,nullptr)==17&&c.forwards==2);
 puts("PASS: production error-query guard before all legacy superclass routes, STA/virtual queries, length extremes, poisoned payload, wrapper canaries and unrelated forwarding");
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.cpp').write_text(pre+body+cases)
 subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(root/'src/kext'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
