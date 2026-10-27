/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * WPA3-Personal policy and frame crypto for the existing IO80211 backend.
 * SAE primitives originate from the pinned AirportRTW/hostap/Mbed TLS import.
 * No Apple ABI types: this exact implementation is exercised by host tests.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../../experimental/wpa3/rtw80211/sae/rtw_sae.h"
#include "../../experimental/wpa3/rtw80211/sae/rtw_sae_crypto.h"
namespace RTW88WPA3 {
inline void wipe(void *p,size_t n){volatile uint8_t*q=(volatile uint8_t*)p;while(n--)*q++=0;}
struct ScopeWipe { void*p;size_t n;~ScopeWipe(){wipe(p,n);} };
inline unsigned le(const uint8_t*p){return p[0]|unsigned(p[1])<<8;}
inline void put(uint8_t*p,unsigned v){p[0]=uint8_t(v);p[1]=uint8_t(v>>8);}
inline uint64_t pn(const uint8_t*p){uint64_t n=0;for(unsigned i=0;i<6;++i)n|=uint64_t(p[i])<<(8*i);return n;}
inline void putpn(uint8_t*p,uint64_t n){for(unsigned i=0;i<6;++i)p[i]=uint8_t(n>>(8*i));}
// IEEE robust action categories, matching Linux ieee80211_is_robust_mgmt_frame.
inline bool robustAction(unsigned category){
    return category!=4 && category!=7 && category!=11 && category!=15 &&
        category!=20 && category!=21 && category!=22 && category!=127;
}
inline bool robustManagement(const uint8_t*f,size_t n){
    if(!f || n<24 || (f[0]&12))return false;
    unsigned sub=f[0]&0xfc;
    return sub==0xa0 || sub==0xc0 ||
        (sub==0xd0 && n>24 && ((f[1]&0x40) || robustAction(f[24])));
}
inline const uint8_t* ie(const uint8_t*p,size_t n,unsigned id,size_t &size){
    size=0;for(size_t i=0;i+2<=n;){size_t z=p[i+1]+2u;if(z>n-i)return nullptr;
        if(p[i]==id){size=z;return p+i;}i+=z;}return nullptr;}
struct Profile {uint8_t rsn[257]={},xe[257]={};size_t rn=0,xn=0;bool h2e=false;};
inline bool profile(const uint8_t*ies,size_t n,Profile &p){
    p={};size_t z;auto*r=ie(ies,n,48,z);if(!r||z<22||le(r+2)!=1||memcmp(r+4,"\x00\x0f\xac\x04",4))return false;
    size_t o=8;unsigned count=le(r+o);o+=2;bool ccmp=false,sae=false;
    if(!count||count>(z-o)/4)return false;
    for(unsigned i=0;i<count;++i,o+=4)ccmp|=!memcmp(r+o,"\x00\x0f\xac\x04",4);
    if(z-o<2)return false;count=le(r+o);o+=2;if(!count||count>(z-o)/4)return false;
    for(unsigned i=0;i<count;++i,o+=4)sae|=!memcmp(r+o,"\x00\x0f\xac\x08",4);
    if(!ccmp||!sae||z-o<2||!(le(r+o)&0x80))return false;o+=2;
    if(o<z){if(z-o<2)return false;count=le(r+o);o+=2;if(count>(z-o)/16)return false;o+=count*16;
        if(o<z&&(z-o!=4||memcmp(r+o,"\x00\x0f\xac\x06",4)))return false;}
    memcpy(p.rsn,r,z);p.rn=z;
    auto*x=ie(ies,n,244,z);if(x){if(z<3||((x[2]&15)+1u)!=z-2)return false;
        memcpy(p.xe,x,z);p.xn=z;p.h2e=(x[2]&0x20)!=0;}
    return true;
}
/* CCM for 3-address CCMP-128. Retain IV and MIC in-place for the existing
 * Ethernet conversion. Authenticate before committing replay state. */
bool ccmp(uint8_t *frame,size_t length,const uint8_t key[16],uint64_t packetNumber,bool encrypt);

class Session {
public:
    struct rtw_sae* crypto=nullptr;Profile ap;
    bool active=false,committed=false,confirmed=false,authorized=false,pending=false;
    unsigned stage=0,error=0,tokenRequests=0;uint8_t own[6]={},peer[6]={};
    uint8_t pmk[32]={},pmkid[16]={},ptk[48]={},tk[16]={},anonce[32]={},snonce[32]={},replay[8]={};
    uint8_t commit[512]={},confirm[34]={};size_t commitLen=0;
    uint8_t gtk[4][16]={},igtk[2][16]={};bool gv[4]={},iv[2]={};
    uint64_t rx[5][18]={},ipn[2]={},txpn=0;bool nonceValid=false;
    void clear(){if(crypto)rtw_sae_end(crypto);crypto=nullptr;wipe(this,sizeof(*this));}
    bool begin(const uint8_t*mac,const uint8_t*bssid,const uint8_t*ssid,size_t sn,const uint8_t*password,size_t pn_,const uint8_t*ies,size_t n){
        clear();if(!profile(ies,n,ap))return false;memcpy(own,mac,6);memcpy(peer,bssid,6);
        crypto=rtw_sae_begin(own,peer,password,pn_,ssid,sn,ap.h2e);if(!crypto)return false;
        int l=rtw_sae_write_commit(crypto,nullptr,0,commit,sizeof(commit));if(l<=0){clear();return false;}commitLen=size_t(l);active=true;stage=1;return true;}
    size_t auth(uint8_t*out){if(!active||!crypto)return 0;put(out,3);put(out+2,committed?2:1);put(out+4,!committed&&ap.h2e?126:0);
        size_t n=committed?34:commitLen;memcpy(out+6,committed?confirm:commit,n);return n+6;}
    /* 1 = retransmit commit/confirm, 2 = start association, 0 = ignore. */
    unsigned receiveAuth(const uint8_t*f,size_t n){
        if(!active||!crypto||n<30||(le(f)&~0x3800u)!=0xb0||memcmp(f+4,own,6)||memcmp(f+10,peer,6)||memcmp(f+16,peer,6)||(le(f+22)&15))return 0;
        unsigned seq=le(f+26),status=le(f+28);auto*b=f+30;size_t size=n-30;
        if(seq==1&&status==76&&!committed){if(size<3||le(b)!=19||++tokenRequests>3)return 0;auto*t=b+2;size_t z=size-2;
            if(ap.h2e){if(z<3||t[0]!=255||t[1]<2||t[1]>z-2||t[2]!=93)return 0;z=t[1]-1;t+=3;}
            if(!z||z>256)return 0;int l=rtw_sae_write_commit(crypto,t,z,commit,sizeof(commit));if(l<=0)return 0;commitLen=size_t(l);return 1;}
        if(seq==1&&status==(ap.h2e?126u:0u)){
            if(!committed){int rc=rtw_sae_rx_commit(crypto,b,size);if(rc){error=0x10000u|unsigned(rc);return 0;}
                if(rtw_sae_write_confirm(crypto,confirm,sizeof(confirm))!=34)return 0;committed=true;stage=2;}
            return 1;}
        if(seq==2&&!status&&committed&&size==34){if(rtw_sae_rx_confirm(crypto,b,size)){error=0x20000;return 0;}
            rtw_sae_keys(crypto,pmk,pmkid);confirmed=true;stage=3;error=0;return 2;}return 0;}
    size_t rsn(uint8_t*out,bool association=true)const{
        static const uint8_t r[]={48,26,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,8,0xc0,0,0,0,0,15,172,6};
        memcpy(out,r,sizeof(r));size_t n=sizeof(r);
        if(association){out[1]=42;out[22]=1;memmove(out+40,out+24,4);memcpy(out+24,pmkid,16);n+=16;}
        if(ap.h2e){out[n++]=244;out[n++]=1;out[n++]=0x20;}return n;}
    bool mic(const uint8_t*e,size_t n)const{if(n<99||n>611)return false;uint8_t copy[611],m[16];memcpy(copy,e,n);memset(copy+81,0,16);rtw_sae_aes_cmac(ptk,copy,n,m);return rtw_sae_crypto_equal(m,e+81,16);}
    size_t reply(uint8_t*out,unsigned step,const uint8_t*counter)const{
        memset(out,0,611);out[0]=2;out[1]=3;out[4]=2;unsigned ki=(step==5?0:8)|0x100|(step==2?0:0x200);out[5]=uint8_t(ki>>8);out[6]=uint8_t(ki);memcpy(out+9,counter,8);
        size_t n=99;if(step==2){memcpy(out+17,snonce,32);size_t z=rsn(out+99);out[97]=uint8_t(z>>8);out[98]=uint8_t(z);n+=z;}
        out[2]=uint8_t((n-4)>>8);out[3]=uint8_t(n-4);rtw_sae_aes_cmac(ptk,out,n,out+81);return n;}
    /* Sender handles EAPOL Ethernet encapsulation; install callback commits
     * controlled-port authorization only after required keys authenticate. */
    template<class Random,class Send> bool eapol(const uint8_t*e,size_t n,Random random,Send send){
        if(!active||!confirmed||n<99||e[0]<1||e[0]>3||e[1]!=3||e[4]!=2)return false;
        size_t total=4+(size_t(e[2])<<8|e[3]);if(total>n||total<99||total>611)return false;n=total;
        unsigned ki=unsigned(e[5])<<8|e[6];size_t kn=size_t(e[97])<<8|e[98];if(kn!=n-99||(ki&7)||(ki&0x0c00))return false;
        const bool m1=(ki&0x3fc8)==0x88,m3=(ki&0x3fc8)==0x13c8,g1=(ki&0x3fc8)==0x1380;
        if(m1){if(nonceValid&&(memcmp(e+9,replay,8)<0||(!pending&&!memcmp(e+9,replay,8))))return false;
            if(!pending||memcmp(anonce,e+17,32)){random(snonce,32);memcpy(anonce,e+17,32);}
            uint8_t ctx[76];bool first=memcmp(own,peer,6)<0;memcpy(ctx,first?own:peer,6);memcpy(ctx+6,first?peer:own,6);
            first=memcmp(snonce,anonce,32)<0;memcpy(ctx+12,first?snonce:anonce,32);memcpy(ctx+44,first?anonce:snonce,32);
            rtw_sae_kdf_sha256(pmk,32,"Pairwise key expansion",ctx,76,ptk,48);memcpy(replay,e+9,8);nonceValid=pending=true;stage=4;
            uint8_t out[611];return send(out,reply(out,2,replay),false);}
        if((!m3&&!g1)||!nonceValid||memcmp(e+9,replay,8)<0||!mic(e,n)||kn<24||(kn&7)||kn>512)return false;
        if(m3&&memcmp(e+17,anonce,32))return false;
        if(g1&&(!authorized||pending))return false;
        bool duplicate=(!pending&&m3)||(!memcmp(e+9,replay,8)&&g1);
        uint8_t plain[512]={};ScopeWipe plainGuard{plain,sizeof(plain)};if(!rtw_sae_aes_unwrap(ptk+16,e+99,kn,plain)){error=2;return false;}
        size_t size=kn-8;uint8_t g[16]={},ig[16]={};ScopeWipe gGuard{g,sizeof(g)},igGuard{ig,sizeof(ig)};unsigned gi=0,ii=0;uint64_t initialIPN=0;bool haveG=false,haveI=false,haveR=false,haveX=false;
        for(size_t o=0;o+2<=size;){auto*p=plain+o;size_t z=p[1]+2u;if(z>size-o){wipe(plain,sizeof(plain));return false;}if(p[0]==221&&p[1]==0)break;
            if(p[0]==48){if(haveR||z!=ap.rn||memcmp(p,ap.rsn,z))return false;haveR=true;}
            if(p[0]==244){if(haveX||z!=ap.xn||memcmp(p,ap.xe,z))return false;haveX=true;}
            if(p[0]==221&&z>=6&&!memcmp(p+2,"\x00\x0f\xac",3)){
                if(p[5]==1){if(haveG||z!=24||(p[6]&0xf8))return false;gi=p[6]&3;memcpy(g,p+8,16);haveG=true;}
                if(p[5]==9){if(haveI||z!=30)return false;ii=le(p+6);if(ii<4||ii>5)return false;ii-=4;initialIPN=pn(p+8);memcpy(ig,p+14,16);haveI=true;}}
            o+=z;}
        if(m3&&(!haveR||(ap.xn&&!haveX)||!haveG||!haveI)){error=3;return false;}
        if(g1&&!haveG&&!haveI)return false;
        if(duplicate){if((haveG&&(!gv[gi]||memcmp(gtk[gi],g,16)))||(haveI&&(!iv[ii]||memcmp(igtk[ii],ig,16))))return false;}
        if(m3&&pending){if(!authorized||memcmp(tk,ptk+32,16)){memcpy(tk,ptk+32,16);txpn=0;memset(rx[4],0,sizeof(rx[4]));}}
        if(haveG&&(!gv[gi]||memcmp(gtk[gi],g,16))){memcpy(gtk[gi],g,16);memset(rx[gi],0,sizeof(rx[gi]));uint64_t initial=pn(e+65);for(auto&v:rx[gi])v=initial;gv[gi]=true;}
        if(haveI&&(!iv[ii]||memcmp(igtk[ii],ig,16))){memcpy(igtk[ii],ig,16);ipn[ii]=initialIPN;iv[ii]=true;}
        wipe(plain,sizeof(plain));wipe(g,sizeof(g));wipe(ig,sizeof(ig));memcpy(replay,e+9,8);pending=false;
        uint8_t out[611];bool sent=send(out,reply(out,m3?4:5,replay),g1);
        if(m3&&sent){authorized=true;stage=5;error=0;}return sent;}
    bool encrypt(uint8_t*f,size_t n){if(!authorized||n<40||txpn>=0xffffffffffffULL)return false;
        size_t h=((le(f)&12)!=0&&(f[0]&0x80))?26:24;auto*v=f+h;uint64_t number=++txpn;
        uint8_t p[6];putpn(p,number);v[0]=p[0];v[1]=p[1];v[2]=0;v[3]=0x20;memcpy(v+4,p+2,4);f[1]|=0x40;return ccmp(f,n,tk,number,true);}
    bool decrypt(uint8_t*f,size_t n){if(!authorized||n<40||!(f[1]&0x40)||memcmp(f+10,peer,6))return false;
        bool mgmt=(f[0]&12)==0;size_t h=!mgmt&&(f[0]&0x80)?26:24;if(n<h+16)return false;auto*v=f+h;
        if(v[2]||(v[3]&0x3f)!=0x20)return false;unsigned id=v[3]>>6,slot=f[4]&1?id:4;
        if(slot==4&&id)return false;if(slot!=4&&!gv[id])return false;
        unsigned tid=mgmt?17:h==26?f[24]&15:16;uint8_t p[]={v[0],v[1],v[4],v[5],v[6],v[7]};uint64_t number=pn(p);
        if(number<=rx[slot][tid]||!ccmp(f,n,slot==4?tk:gtk[id],number,false))return false;rx[slot][tid]=number;return true;}
    bool bip(uint8_t*f,size_t &n){if(!authorized||n<42||memcmp(f+10,peer,6)||memcmp(f+16,peer,6))return false;
        auto*m=f+n-18;if(m[0]!=76||m[1]!=16)return false;unsigned i=le(m+2);if(i<4||i>5||!iv[i-4])return false;i-=4;
        uint64_t number=pn(m+4);if(number<=ipn[i])return false;uint8_t aad[20],saved[8],mac[16];aad[0]=f[0];aad[1]=f[1]&0xc7;memcpy(aad+2,f+4,18);memcpy(saved,m+10,8);memset(m+10,0,8);
        const uint8_t*parts[]={aad,f+24};size_t lens[]={20,n-24};rtw_sae_aes_cmac_vector(igtk[i],2,parts,lens,mac);memcpy(m+10,saved,8);
        if(!rtw_sae_crypto_equal(saved,mac,8))return false;ipn[i]=number;n-=18;return true;}
    bool management(uint8_t*f,size_t &n,bool &authenticated){
        authenticated=false;
        if(!f || n<24 || (f[0]&12))return false;
        unsigned fc=le(f),sub=fc&0xfc;
        if(!robustManagement(f,n))return sub!=0xd0 || n>24;
        if((fc&0x8700)||(le(f+22)&15)||memcmp(f+10,peer,6)||
           memcmp(f+16,peer,6)||!authorized)return false;
        if(f[4]&1){if((fc&0x4000)||!bip(f,n))return false;}
        else{
            if(memcmp(f+4,own,6)||!decrypt(f,n))return false;
            memmove(f+24,f+32,n-40);n-=16;f[1]&=~0x40;
        }
        authenticated=true;return true;
    }
};
}
