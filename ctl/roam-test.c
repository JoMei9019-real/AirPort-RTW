/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){
    if(argc>2){fprintf(stderr,"Usage: rtw88-roam [aa:bb:cc:dd:ee:ff]\n");return 2;}
    io_service_t service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("AirPortRTW"));
    if(!service){fprintf(stderr,"AirPortRTW service not found\n");return 1;}
    if(argc==1){
        CFTypeRef value=IORegistryEntryCreateCFProperty(service,CFSTR("ROAM_K_CANDIDATES"),kCFAllocatorDefault,0);
        if(value && CFGetTypeID(value)==CFDataGetTypeID()){
            CFDataRef data=(CFDataRef)value;const UInt8 *p=CFDataGetBytePtr(data);CFIndex n=CFDataGetLength(data);
            for(CFIndex i=0;i+6<=n;i+=6)printf("%02x:%02x:%02x:%02x:%02x:%02x\n",p[i],p[i+1],p[i+2],p[i+3],p[i+4],p[i+5]);
            if(!n)fprintf(stderr,"No fresh Neighbor Report candidates\n");
        }else fprintf(stderr,"Candidate diagnostics unavailable\n");
        if(value)CFRelease(value);IOObjectRelease(service);return 0;
    }
    unsigned v[6];int consumed=0;
    if(strlen(argv[1])!=17 || sscanf(argv[1],"%2x:%2x:%2x:%2x:%2x:%2x%n",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5],&consumed)!=6 || consumed!=17){
        fprintf(stderr,"Invalid BSSID\n");IOObjectRelease(service);return 2;
    }
    if(geteuid()!=0){fprintf(stderr,"Use sudo to request an AP switch\n");IOObjectRelease(service);return 1;}
    UInt8 mac[6];for(unsigned i=0;i<6;++i)mac[i]=v[i];
    CFDataRef data=CFDataCreate(kCFAllocatorDefault,mac,6);
    kern_return_t result=IORegistryEntrySetCFProperty(service,CFSTR("RoamToBSSID"),data);
    CFRelease(data);IOObjectRelease(service);
    printf("Request result: 0x%08x (%s)\n",result,result==KERN_SUCCESS?"accepted; check ROAM_SWITCH_RESULT for outcome":"rejected before switch");
    return result==KERN_SUCCESS?0:1;
}
