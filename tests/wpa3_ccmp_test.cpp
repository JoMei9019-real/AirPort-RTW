#include "../src/kext/RTW88WPA3.hpp"
#include "wpa3_ccmp_vectors.hpp"
#include <cassert>
#include <cstdio>
#include <vector>
using namespace RTW88WPA3;
int main(){
    const size_t lengths[]={0,1,2,7,15,16,17,31,32,33,255,256,257,1499,1500,1501,8191,8192};
    const uint64_t numbers[]={1,256,65535,0x010203040506ULL,0xffffffffffffULL};
    unsigned index=0;
    for(unsigned kind=0;kind<3;++kind)for(size_t len:lengths){
        bool qos=kind==0,mgmt=kind==2;size_t h=qos?26:24,n=h+16+len;
        // Shift the buffer through every possible uint64_t alignment, with guards.
        size_t offset=8+index%8;std::vector<uint8_t> buf(offset+n+8,0xa5);
        uint8_t*f=buf.data()+offset;memset(f,0,n);
        f[0]=mgmt?0xd0:qos?0x88:8;f[1]=mgmt?0x40:0x42;
        for(unsigned i=0;i<18;++i)f[4+i]=uint8_t(2+i*7);
        f[22]=0x50;f[23]=0x12;if(qos)f[24]=uint8_t(index%16);
        uint64_t number=numbers[index%5];uint8_t p[6],key[16];putpn(p,number);
        auto*v=f+h;v[0]=p[0];v[1]=p[1];v[2]=0;v[3]=uint8_t(0x20|((index%4)<<6));memcpy(v+4,p+2,4);
        for(unsigned i=0;i<16;++i)key[i]=uint8_t(i*13+index*11);
        for(size_t i=0;i<len;++i)f[h+8+i]=uint8_t(i*37+index*19);
        auto plain=std::vector<uint8_t>(f,f+n);
        assert(ccmp(f,n,key,number,true));
        uint8_t digest[32];rtw_sae_sha256(f,n,digest);
        char hex[65];for(unsigned i=0;i<32;++i)snprintf(hex+2*i,3,"%02x",digest[i]);
        assert(!strcmp(hex,ccmpAnswers[index]));
        auto encrypted=std::vector<uint8_t>(f,f+n);
        f[n-1]^=1;assert(!ccmp(f,n,key,number,false)); // forged tag
        memcpy(f,encrypted.data(),n);f[10]^=1;assert(!ccmp(f,n,key,number,false)); // forged transmitter/AAD
        if(len){memcpy(f,encrypted.data(),n);f[h+8]^=1;assert(!ccmp(f,n,key,number,false));}
        memcpy(f,encrypted.data(),n);assert(ccmp(f,n,key,number,false));
        assert(!memcmp(f,plain.data(),h+8+len));
        for(size_t i=0;i<offset;++i)assert(buf[i]==0xa5);
        for(size_t i=offset+n;i<buf.size();++i)assert(buf[i]==0xa5);
        memcpy(f,encrypted.data(),n);assert(!ccmp(f,n,key,0,false));
        assert(!ccmp(f,n,key,0x1000000000000ULL,false));
        ++index;
    }
    assert(index==sizeof(ccmpAnswers)/sizeof(*ccmpAnswers));
    uint8_t oversized[24+16+8193]={};assert(!ccmp(oversized,sizeof(oversized),oversized,1,true));
    puts("PASS: 54 independent AESCCM answers, block/MPDU boundaries, unaligned buffers and forgery rejection");
}
