#include "../src/kext/RTW88AssocWire.hpp"
#include <cassert>
#include <vector>
#include <cstdio>
using namespace RTW88AssocWire;
void put(std::vector<uint8_t>&p,size_t o,uint32_t v){for(unsigned i=0;i<4;++i)p[o+i]=uint8_t(v>>(8*i));}
std::vector<uint8_t> request(unsigned upper,unsigned cipher,unsigned length){
 std::vector<uint8_t> p(PasswordPrefixSize);put(p,0,1);put(p,4,2);put(p,8,1);put(p,12,upper);put(p,16,4);memcpy(p.data()+20,"test",4);p[52]=2;put(p,60,1);put(p,64,length);put(p,68,cipher);memset(p.data()+76,0x42,64);return p;
}
int main(){
 Personal out;
 for(unsigned upper:{8u,4096u,4104u})for(unsigned n:{1u,16u,32u,33u,63u}) {
  auto p=request(upper,10,n);assert(decode(p.data(),p.size(),out));assert(out.keyLength==n&&out.cipher==10);
  assert(decode(p.data(),PrefixSize,out)==(n<=32));
  for(unsigned i=0;i<n;++i){p[76+i]=0;assert(!decode(p.data(),p.size(),out));p[76+i]=0x42;}
 }
 for(unsigned length:{0u,64u,65u,0xffffffffu}){auto p=request(4096,10,length);assert(!decode(p.data(),p.size(),out));}
 for(unsigned cipher:{0u,4u,6u,7u}){auto p=request(4096,cipher,32);assert(!decode(p.data(),p.size(),out));}
 auto p=request(8,6,32);assert(decode(p.data(),PrefixSize,out));assert(out.cipher==6); // PMK remains PMK.
 p=request(8,10,16);p[52]=3;assert(!decode(p.data(),p.size(),out));
 p=request(8192,10,16);assert(!decode(p.data(),p.size(),out)); // FT-SAE unsupported.
 for(size_t n=0;n<PasswordPrefixSize;++n){auto shortBuffer=std::vector<uint8_t>(p.begin(),p.begin()+n);if(n!=PrefixSize)assert(!decode(shortBuffer.data(),n,out));}
 wipe(&out,sizeof(out));puts("PASS: native menu credential type/length validation; PMK never decoded as SAE password");
}
