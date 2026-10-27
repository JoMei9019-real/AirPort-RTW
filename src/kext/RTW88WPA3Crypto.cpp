/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Isolated optimized scalar CCMP implementation. Compile this translation
 * unit with optimization; keep the established IOKit/MLME flags unchanged.
 */
#include "RTW88WPA3.hpp"
#include "RTW88WPA3AES.hpp"
namespace RTW88WPA3 {
namespace {
// memcpy loads/stores keep unaligned packet buffers and aliasing well-defined.
inline void xorBlock(uint8_t*out,const uint8_t*a,const uint8_t*b){
    for(unsigned j=0;j<16;j+=8){uint64_t x,y;memcpy(&x,a+j,8);memcpy(&y,b+j,8);x^=y;memcpy(out+j,&x,8);}
}
inline void counter(uint8_t*ctr,size_t block){ctr[14]=uint8_t(block>>8);ctr[15]=uint8_t(block);}
template<bool Encrypt>
void payload(const AES128&aes,uint8_t*data,size_t len,uint8_t*tag,uint8_t*ctr){
    uint8_t stream[16];
    if(!Encrypt && len){counter(ctr,1);aes.encrypt(ctr,stream);}
    const size_t full=len&~size_t(15);
    for(size_t o=0;o<full;o+=16){
        if constexpr(Encrypt){
            xorBlock(tag,tag,data+o);counter(ctr,o/16+1);
            aes.encryptPair(tag,ctr,tag,stream);
            xorBlock(data+o,data+o,stream);
        }else{
            xorBlock(data+o,data+o,stream);xorBlock(tag,tag,data+o);
            if(o+16<len){counter(ctr,o/16+2);aes.encryptPair(tag,ctr,tag,stream);}
            else aes.encrypt(tag,tag);
        }
    }
    const size_t tail=len-full;
    if(tail){
        if constexpr(!Encrypt)for(size_t j=0;j<tail;++j)data[full+j]^=stream[j];
        for(size_t j=0;j<tail;++j)tag[j]^=data[full+j];
        if constexpr(Encrypt){
            counter(ctr,full/16+1);aes.encryptPair(tag,ctr,tag,stream);
            for(size_t j=0;j<tail;++j)data[full+j]^=stream[j];
        }else aes.encrypt(tag,tag);
    }
}
}
bool ccmp(uint8_t*f,size_t n,const uint8_t key[16],uint64_t number,bool encrypt){
    if(!f||n<40||number==0||number>0xffffffffffffULL)return false;
    unsigned fc=le(f);bool mgmt=(fc&12)==0,qos=!mgmt&&(fc&0x80);
    if((fc&0x300)==0x300||(fc&0x8400)||(le(f+22)&15))return false;
    size_t h=qos?26:24;if(n<h+16||n-h-16>8192)return false;
    AES128 aes(key);
    size_t len=n-h-16;auto*v=f+h;uint8_t nonce[13]={},aad[24]={};
    nonce[0]=mgmt?0x10:qos?(f[24]&15):0;memcpy(nonce+1,f+10,6);
    for(unsigned i=0;i<6;++i)nonce[7+i]=uint8_t(number>>(8*(5-i)));
    aad[0]=f[0]&(mgmt?0xff:0x8f);aad[1]=f[1]&0xc7;
    memcpy(aad+2,f+4,18);aad[20]=f[22]&15;aad[21]=0;
    if(qos)aad[22]=f[24]&15;
    uint8_t ctr[16]={1},s0[16],tag[16]={0x59};memcpy(ctr+1,nonce,13);
    memcpy(tag+1,nonce,13);tag[14]=uint8_t(len>>8);tag[15]=uint8_t(len);
    aes.encryptPair(ctr,tag,s0,tag);
    uint8_t ad[32]={0};ad[1]=qos?24:22;memcpy(ad+2,aad,ad[1]);
    for(unsigned o=0;o<32;o+=16){xorBlock(tag,tag,ad+o);aes.encrypt(tag,tag);}
    uint8_t *data=v+8;
    if(encrypt)payload<true>(aes,data,len,tag,ctr);
    else payload<false>(aes,data,len,tag,ctr);
    for(unsigned j=0;j<8;++j)tag[j]^=s0[j];
    if(!encrypt)return rtw_sae_crypto_equal(tag,data+len,8);
    memcpy(data+len,tag,8);
    return true;
}
}
