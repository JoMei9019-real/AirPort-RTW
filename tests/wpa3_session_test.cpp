#include "../src/kext/RTW88WPA3.hpp"
#include <cassert>
#include <vector>
#include <cstdio>
using namespace RTW88WPA3;
std::vector<uint8_t> hex(const char*s){std::vector<uint8_t>r;while(*s){unsigned v;assert(sscanf(s,"%2x",&v)==1);r.push_back(uint8_t(v));s+=2;}return r;}
void frame(uint8_t*f,const uint8_t*own,const uint8_t*peer,unsigned seq,unsigned status,const uint8_t*b,size_t n){memset(f,0,600);f[0]=0xb0;memcpy(f+4,own,6);memcpy(f+10,peer,6);memcpy(f+16,peer,6);put(f+24,3);put(f+26,seq);put(f+28,status);memcpy(f+30,b,n);}
void scenario(bool h2e,bool transition){
    const uint8_t own[]={2,0,0,0,0,1},peer[]={2,0,0,0,0,2},pw[]="WPA3 test password",ssid[]="test";
    auto ies=hex("301a0100000fac040100000fac040100000fac08c0000000000fac06");
    if(transition) {
        ies=hex("301e0100000fac040100000fac040200000fac02000fac0880000000000fac06");
    }
    if(h2e){ies.push_back(244);ies.push_back(1);ies.push_back(0x20);}
    Session s;assert(s.begin(own,peer,ssid,4,pw,sizeof(pw)-1,ies.data(),ies.size()));
    uint8_t selected[64];size_t selectedLength=s.rsn(selected);assert(selectedLength>=44&&selected[19]==8&&selected[14]==1&&selected[15]==0);
    auto*ap=rtw_sae_begin(peer,own,pw,sizeof(pw)-1,ssid,4,h2e);assert(ap);
    uint8_t auth[600],pcommit[512],pconfirm[34];size_t n=s.auth(auth);assert(n>6);
    assert(rtw_sae_rx_commit(ap,auth+6,n-6)==0);
    int cn=rtw_sae_write_commit(ap,nullptr,0,pcommit,sizeof(pcommit));assert(cn>0);
    frame(auth,own,peer,1,h2e?126:0,pcommit,cn);assert(s.receiveAuth(auth,30+cn)==1);
    assert(rtw_sae_write_confirm(ap,pconfirm,sizeof(pconfirm))==34);
    n=s.auth(auth);assert(le(auth+2)==2);assert(rtw_sae_rx_confirm(ap,auth+6,n-6)==0);
    frame(auth,own,peer,2,0,pconfirm,34);auth[33]^=1;assert(!s.receiveAuth(auth,64));auth[33]^=1;assert(s.receiveAuth(auth,64)==2);
    uint8_t apPMK[32],id[16];rtw_sae_keys(ap,apPMK,id);assert(!memcmp(s.pmk,apPMK,32));
    std::vector<uint8_t> reply;auto sender=[&](const uint8_t*p,size_t z,bool){reply.assign(p,p+z);return true;};
    uint8_t m1[99]={};m1[0]=2;m1[1]=3;m1[3]=95;m1[4]=2;m1[6]=0x88;m1[16]=1;memset(m1+17,0x55,32);
    assert(s.eapol(m1,sizeof(m1),[](uint8_t*p,size_t z){memset(p,0x33,z);},sender));assert(reply.size()>99&&s.pending&&!s.authorized);
    auto savedReply=reply;assert(s.eapol(m1,sizeof(m1),[](uint8_t*,size_t){assert(false);},sender));assert(reply==savedReply);
    uint8_t ctx[76],ptk[48];memcpy(ctx,own,6);memcpy(ctx+6,peer,6);memset(ctx+12,0x33,32);memset(ctx+44,0x55,32);
    rtw_sae_kdf_sha256(apPMK,32,"Pairwise key expansion",ctx,76,ptk,48);assert(!memcmp(ptk,s.ptk,48));
    std::vector<uint8_t> kd=ies;auto gtk=hex("dd16000fac010100000102030405060708090a0b0c0d0e0f");auto igtk=hex("dd1c000fac090400000000000000101112131415161718191a1b1c1d1e1f");
    kd.insert(kd.end(),gtk.begin(),gtk.end());kd.insert(kd.end(),igtk.begin(),igtk.end());
    if(kd.size()%8){kd.push_back(221);while(kd.size()%8)kd.push_back(0);}
    std::vector<uint8_t>m3(99+kd.size()+8);m3[0]=2;m3[1]=3;m3[2]=uint8_t((m3.size()-4)>>8);m3[3]=uint8_t(m3.size()-4);m3[4]=2;m3[5]=0x13;m3[6]=0xc8;m3[16]=2;memset(m3.data()+17,0x55,32);m3[97]=uint8_t((kd.size()+8)>>8);m3[98]=uint8_t(kd.size()+8);
    rtw_sae_aes_wrap(ptk+16,kd.data(),kd.size(),m3.data()+99);rtw_sae_aes_cmac(ptk,m3.data(),m3.size(),m3.data()+81);
    m3[81]^=1;assert(!s.eapol(m3.data(),m3.size(),[](uint8_t*,size_t){},sender));assert(!s.authorized);m3[81]^=1;
    assert(s.eapol(m3.data(),m3.size(),[](uint8_t*,size_t){},sender));assert(s.authorized&&s.stage==5&&s.gv[1]&&s.iv[0]);
    s.txpn=123;s.rx[1][0]=42;s.ipn[0]=10;assert(s.eapol(m3.data(),m3.size(),[](uint8_t*,size_t){},sender));assert(s.txpn==123&&s.rx[1][0]==42&&s.ipn[0]==10);
    uint8_t group[44]={0xc0};memset(group+4,255,6);memcpy(group+10,peer,6);memcpy(group+16,peer,6);group[24]=3;group[26]=76;group[27]=16;group[28]=4;group[30]=11;
    uint8_t aad[20]={0xc0},tag[16];memcpy(aad+2,group+4,18);const uint8_t*parts[]={aad,group+24};size_t lens[]={20,20};rtw_sae_aes_cmac_vector(s.igtk[0],2,parts,lens,tag);memcpy(group+36,tag,8);size_t gn=44;
    group[36]^=1;assert(!s.bip(group,gn));group[36]^=1;assert(s.bip(group,gn)&&gn==26);gn=44;assert(!s.bip(group,gn));
    uint8_t mgmt[42]={0xc0,0x40};memcpy(mgmt+4,own,6);memcpy(mgmt+10,peer,6);memcpy(mgmt+16,peer,6);mgmt[24]=1;mgmt[27]=0x20;mgmt[32]=3;
    assert(ccmp(mgmt,sizeof(mgmt),s.tk,1,true));uint8_t retry[42];memcpy(retry,mgmt,42);mgmt[41]^=1;assert(!s.decrypt(mgmt,42));memcpy(mgmt,retry,42);assert(s.decrypt(mgmt,42));assert(!s.decrypt(retry,42));
    s.clear();assert(!s.active&&!s.authorized&&!s.crypto);rtw_sae_end(ap);
}
int main(){
    // Independent Python cryptography AESCCM known answer, eight-byte tag.
    auto expected=hex("88420000020000000001020000000002020000000003000005000100002000000000b2903e707f5ccaefc1059d78444f379c1488720a86d77eac7c54");
    auto plain=hex("aaaa03000000080068656c6c6f2057504133");uint8_t key[16];for(unsigned i=0;i<16;++i)key[i]=i;
    auto f=expected;assert(ccmp(f.data(),f.size(),key,1,false));assert(!memcmp(f.data()+34,plain.data(),plain.size()));assert(ccmp(f.data(),f.size(),key,1,true));assert(f==expected);
    Profile rejected;auto pskOnly=hex("30140100000fac040100000fac040100000fac020000");assert(!profile(pskOnly.data(),pskOnly.size(),rejected));
    scenario(false,false);scenario(true,false);scenario(false,true);scenario(true,true);puts("PASS: production SAE/4-way handshake, PMF integrity/replay and CCMP known answer");
}
