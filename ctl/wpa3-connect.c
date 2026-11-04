/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
static void wipe(void*p,size_t n){volatile unsigned char*q=p;while(n--)*q++=0;}
int main(int argc,char**argv){
    if(argc==2&&!strcmp(argv[1],"--help")){puts("Usage: sudo ./wpa3-connect SSID AP-BSSID\nDisconnect Wi-Fi first, then scan in the Wi-Fi menu. Password is prompted privately.\nBeta: no saved password, automatic reconnect or WPA3 roaming.");return 0;}
    if(argc!=3||!strlen(argv[1])||strlen(argv[1])>32){fprintf(stderr,"Use --help for usage.\n");return 1;}
    if(geteuid()!=0){fprintf(stderr,"Run with sudo.\n");return 1;}
    unsigned v[6];int used=0;
    if(sscanf(argv[2],"%2x:%2x:%2x:%2x:%2x:%2x%n",v,v+1,v+2,v+3,v+4,v+5,&used)!=6||argv[2][used])return 1;
    UInt8 bssid[6];for(unsigned i=0;i<6;++i)bssid[i]=(UInt8)v[i];if(bssid[0]&1)return 1;
    io_service_t service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("AirPortRTW"));
    if(!service){fprintf(stderr,"AirPortRTW not loaded.\n");return 1;}
    char*input=getpass("WPA3 password: ");if(!input){IOObjectRelease(service);return 1;}
    size_t n=strlen(input);if(!n||n>63){wipe(input,n);IOObjectRelease(service);return 1;}
    CFMutableDictionaryRef request=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFMutableDictionaryRef outer=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFDataRef ssid=CFDataCreate(NULL,(const UInt8*)argv[1],(CFIndex)strlen(argv[1]));
    CFMutableDataRef password=CFDataCreateMutable(NULL,(CFIndex)n);CFDataAppendBytes(password,(const UInt8*)input,(CFIndex)n);wipe(input,n);
    CFDataRef address=CFDataCreate(NULL,bssid,6);
    CFDictionarySetValue(request,CFSTR("SSID"),ssid);CFDictionarySetValue(request,CFSTR("Password"),password);CFDictionarySetValue(request,CFSTR("BSSID"),address);
    CFDictionarySetValue(outer,CFSTR("WPA3Connect"),request);
    kern_return_t r=IORegistryEntrySetCFProperties(service,outer);
    wipe(CFDataGetMutableBytePtr(password),n);
    CFRelease(ssid);CFRelease(password);CFRelease(address);CFRelease(request);CFRelease(outer);IOObjectRelease(service);
    if(r!=KERN_SUCCESS){fprintf(stderr,"Join rejected: 0x%08x. Disconnect first, refresh the scan, and verify the BSSID supports SAE/CCMP/PMF.\n",r);return 1;}
    puts("WPA3 join submitted; this does not yet confirm authentication or DHCP.\nCheck: ioreg -r -c AirPortRTW -l | grep -E 'WPA3(Stage|Error|Active)'\nStage 5 = four-way handshake completed. Then verify DHCP and traffic.");return 0;
}
