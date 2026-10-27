/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Isolated optimized scalar CCMP implementation. Compile this translation
 * unit with optimization; keep the established IOKit/MLME flags unchanged.
 */
#include "RTW88WPA3.hpp"
#include "RTW88WPA3AES.hpp"
namespace RTW88WPA3 {
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
    aes.encrypt(ctr,s0);memcpy(tag+1,nonce,13);tag[14]=uint8_t(len>>8);tag[15]=uint8_t(len);
    aes.encrypt(tag,tag);
    uint8_t ad[32]={0};ad[1]=qos?24:22;memcpy(ad+2,aad,ad[1]);
    for(unsigned o=0;o<32;o+=16){for(unsigned j=0;j<16;++j)tag[j]^=ad[o+j];aes.encrypt(tag,tag);}
    uint8_t *data=v+8;
    if(!encrypt){for(size_t o=0;o<len;o+=16){unsigned block=unsigned(o/16+1);ctr[14]=uint8_t(block>>8);ctr[15]=uint8_t(block);uint8_t stream[16];aes.encrypt(ctr,stream);for(size_t j=0;j<16&&o+j<len;++j)data[o+j]^=stream[j];}}
    for(size_t o=0;o<len;o+=16){for(size_t j=0;j<16&&o+j<len;++j)tag[j]^=data[o+j];aes.encrypt(tag,tag);}
    for(unsigned j=0;j<8;++j)tag[j]^=s0[j];
    if(!encrypt)return rtw_sae_crypto_equal(tag,data+len,8);
    memcpy(data+len,tag,8);
    for(size_t o=0;o<len;o+=16){unsigned block=unsigned(o/16+1);ctr[14]=uint8_t(block>>8);ctr[15]=uint8_t(block);uint8_t stream[16];aes.encrypt(ctr,stream);for(size_t j=0;j<16&&o+j<len;++j)data[o+j]^=stream[j];}
    return true;
}
}
