/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// IEEE 802.11 Radio Measurement wire helpers. No hardware access or allocation.
namespace RTW88RRM {
constexpr unsigned MaxRequests=8, MaxChannels=16, MaxReports=16, MaxBody=768;
struct Request {
    uint8_t token=0, flags=0, type=0, opClass=0, channel=0, mode=0, bssid[6]={};
    uint16_t randomTU=0, durationTU=0;
    uint8_t ssid[32]={}, ssidLength=0, detail=2, eids[32]={};
    uint8_t channels[MaxChannels]={}, channelCount=0;
    bool last=false, unsupported=false;
};
struct Requests { Request entries[MaxRequests]; unsigned count=0, offset=0; uint8_t dialog=0; };
struct Observation {
    uint64_t seenMs=0, startTSF=0;
    uint32_t generation=0, parentTSF=0;
    uint16_t durationTU=0, bodyLength=0;
    int16_t signal=0;
    uint8_t channel=0, phy=0, body[MaxBody]={};
    bool beacon=false;
};
struct Record {
    uint8_t bssid[6]={},ssid_len=0;
    char ssid[33]={};
    Observation measurement;
};
struct State {
    struct Failure {
        uint64_t ms=0;
        uint8_t dialog=0,token=0,type=0,opClass=0,channel=0,mode=0,status=0,flags=0;
        uint16_t durationTU=0;
        const char *reason="none";
    } failure;
    Requests incoming, requests;
    Observation scratch;
    Observation capture;
    Record cache[32]; // Backend heap storage, never added to IOCTL BSS stack copies.
    uint8_t source[6]={}, tx[280]={}, plan[MaxChannels]={};
    unsigned phase=0,index=0,planCount=0,scanMode=0,dwellMs=0;
    uint32_t generation=0;
    uint64_t deadline=0,lastRequestMs=0,clockTSF=0,clockUs=0,scanStartUs=0,scanStartTSF=0,baseTSF=0,baseUs=0;
    unsigned scanChannel=0;
    bool advertised=false,scanOwned=false;
    const char *stage="idle";
    uint32_t received=0,invalid=0,busy=0,reports=0,empty=0,incapable=0,refused=0,
             txFailed=0,canceled=0,scans=0,truncated=0,ack=0,noack=0,actionDropped=0;
    uint8_t lastDialog=0,lastToken=0,lastMode=0,lastChannel=0,lastStatus=0;
    unsigned parseOffset=0;
    uint32_t btmReadyDrops=0,rmReadyDrops=0,linkUnsupported=0,captureOversize=0;
    uint8_t lastOpClass=0,lastType=0,lastFlags=0;
    uint16_t lastDurationTU=0;
    unsigned planRequested=0,planDisabled=0,planPassiveOnly=0;
};
inline uint16_t le16(const uint8_t*p){return uint16_t(p[0])|(uint16_t(p[1])<<8);}
inline void put16(uint8_t*p,uint16_t n){p[0]=uint8_t(n);p[1]=uint8_t(n>>8);}
inline void put32(uint8_t*p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=uint8_t(n>>(8*i));}
inline void put64(uint8_t*p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=uint8_t(n>>(8*i));}
inline bool broadcast(const uint8_t*p){for(unsigned i=0;i<6;++i)if(p[i]!=255)return false;return true;}
inline bool channelInClass(unsigned op,unsigned ch) {
    switch(op) {
    case 81:return ch>=1&&ch<=13; case 82:return ch==14;
    case 115:return ch>=36&&ch<=48&&!(ch%4);
    case 118:return ch>=52&&ch<=64&&!(ch%4);
    case 121:return ch>=100&&ch<=144&&!(ch%4);
    case 124:return ch>=149&&ch<=161&&(ch%4)==1;
    case 125:return ch>=149&&ch<=177&&(ch%4)==1;
    default:return false; // No guessed country-specific or wide-band mapping.
    }
}
inline bool supportedClass(unsigned op) {
    return op==81||op==82||op==115||op==118||op==121||op==124||op==125;
}
inline uint8_t operatingClass(unsigned ch) {
    const uint8_t classes[]={81,82,115,118,121,125};
    for(auto c:classes)if(channelInClass(c,ch))return c;return 0;
}
inline bool parse(const uint8_t*p,size_t n,Requests &out) {
    out={};
    if(!p||n<5||n>1024||p[0]!=5||p[1]!=0)return false;
    out.dialog=p[2];const bool repeated=le16(p+3)!=0;
    size_t pos=5;
    while(pos<n) {
        out.offset=unsigned(pos);
        if(n-pos<2||p[pos+1]>n-pos-2)return false;
        const unsigned id=p[pos],len=p[pos+1];const uint8_t*v=p+pos+2;
        if(id==38) {
            if(len<3||out.count==MaxRequests)return false;
            auto &r=out.entries[out.count++];r.token=v[0];r.flags=v[1];r.type=v[2];
            r.unsupported=repeated||(r.flags&0xe3)||r.type!=5;
            if(r.type==5) {
                if(len<16)return false;
                r.opClass=v[3];r.channel=v[4];r.randomTU=le16(v+5);
                r.durationTU=le16(v+7);r.mode=v[9];memcpy(r.bssid,v+10,6);
                // Mandatory duration and repeated/parallel/enable operations are
                // not claimed by this bounded software scanner.
                r.unsupported|=(r.flags&16)||r.mode>2;
                if(!broadcast(r.bssid)&&(r.bssid[0]&1))r.unsupported=true;
                uint8_t addressBits=0;for(auto byte:r.bssid)addressBits|=byte;
                if(!addressBits)r.unsupported=true;
                unsigned seen=0;
                for(size_t s=16;s<len;) {
                    if(len-s<2||v[s+1]>len-s-2)return false;
                    unsigned sid=v[s],sl=v[s+1];const uint8_t*q=v+s+2;
                    unsigned bit=sid==0?1:sid==1?2:sid==2?4:sid==10?8:sid==164?16:0;
                    if(bit&&(seen&bit))return false;seen|=bit;
                    if(sid==0){if(sl>32)return false;r.ssidLength=sl;memcpy(r.ssid,q,sl);}
                    else if(sid==1){if(sl!=2)return false;if(q[0])r.unsupported=true;}
                    else if(sid==2){if(sl!=1||q[0]>2)return false;r.detail=q[0];}
                    else if(sid==10){if(!sl)return false;for(unsigned i=0;i<sl;++i)r.eids[q[i]/8]|=uint8_t(1U<<(q[i]%8));}
                    else if(sid==51){
                        if(sl<2)return false;
                        if(q[0]!=r.opClass)r.unsupported=true;
                        for(unsigned i=1;i<sl;++i){
                            bool duplicate=false;for(unsigned j=0;j<r.channelCount;++j)duplicate|=r.channels[j]==q[i];
                            if(!duplicate){if(r.channelCount==MaxChannels)r.unsupported=true;else r.channels[r.channelCount++]=q[i];}
                        }
                    } else if(sid==164){if(sl!=1||q[0]>1)return false;r.last=q[0];}
                    else if(sid!=221)r.unsupported=true;
                    s+=sl+2;
                }
                if((seen&8)&&r.detail!=1)r.unsupported=true;
                if(r.channel==255&&!r.channelCount)r.unsupported=true;
                if(r.mode!=2&&(!r.durationTU||r.durationTU>195))r.unsupported=true;
            }
        }
        pos+=len+2;
    }
    out.offset=0;return out.count!=0;
}
inline bool requestedChannel(const Request&r,unsigned ch) {
    if(!channelInClass(r.opClass,ch))return false;
    if(!r.channel)return true;
    if(r.channel!=255)return ch==r.channel;
    for(unsigned i=0;i<r.channelCount;++i)if(r.channels[i]==ch)return true;
    return false;
}
inline size_t emptyReport(uint8_t*out,size_t cap,uint8_t dialog,uint8_t token,uint8_t type,uint8_t mode) {
    if(!out||cap<8)return 0;
    const uint8_t b[]={5,1,dialog,39,3,token,mode,type};memcpy(out,b,sizeof(b));return sizeof(b);
}
// One measurement element per action frame; complete reported frame bodies
// are split at IE boundaries, with standard fragment/last indications.
inline size_t report(uint8_t*out,size_t cap,const Request&r,uint8_t dialog,
                     const uint8_t*bssid,const Observation&o,size_t &offset,
                     unsigned reportID,unsigned fragment,bool lastBSS) {
    if(!out||cap<260||o.bodyLength<12||o.bodyLength>MaxBody)return 0;
    size_t n=emptyReport(out,cap,dialog,r.token,5,0);
    uint8_t *b=out+n;
    b[0]=operatingClass(o.channel);b[1]=o.channel;
    put64(b+2,r.mode==2?0:o.startTSF);put16(b+10,r.mode==2?0:o.durationTU);
    b[12]=o.phy;b[13]=o.signal>=0||o.signal< -127?255:o.signal<=-110?0:uint8_t(2*(o.signal+110));
    b[14]=255;memcpy(b+15,bssid,6);b[21]=0;
    put32(b+22,r.mode==2?0:o.parentTSF);n+=26;
    if(r.detail) {
        const size_t sub=n;out[n++]=1;out[n++]=0;
        if(!offset){memcpy(out+n,o.body,12);n+=12;offset=12;}
        while(offset<o.bodyLength) {
            if(o.bodyLength-offset<2||o.body[offset+1]>o.bodyLength-offset-2)return 0;
            const size_t bytes=size_t(o.body[offset+1])+2;
            const unsigned id=o.body[offset];
            if(r.detail==2||(r.eids[id/8]&(1U<<(id%8)))) {
                if(n+bytes>248)break; // Reserve fragment + last-indication space.
                memcpy(out+n,o.body+offset,bytes);n+=bytes;
            }
            offset+=bytes;
        }
        if(offset<o.bodyLength&&n==sub+2)return 0; // An oversized indivisible IE.
        out[sub+1]=uint8_t(n-sub-2);
        out[n++]=2;out[n++]=2;out[n++]=uint8_t(reportID);
        out[n++]=uint8_t(fragment|(offset<o.bodyLength?128:0));
    } else offset=o.bodyLength;
    if(r.last){out[n++]=164;out[n++]=1;out[n++]=(lastBSS&&offset==o.bodyLength)?1:0;}
    out[4]=uint8_t(n-5);return n;
}
}
