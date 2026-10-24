/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static io_service_t service;
static char status[32768];

static char *string_property(CFStringRef key) {
    CFTypeRef value=IORegistryEntryCreateCFProperty(service,key,kCFAllocatorDefault,0);
    char *text=NULL;
    if(value && CFGetTypeID(value)==CFStringGetTypeID()) {
        CFIndex length=CFStringGetMaximumSizeForEncoding(CFStringGetLength(value),kCFStringEncodingUTF8)+1;
        if(length>0 && length<=262144) {
            text=calloc((size_t)length,1);
            if(text && !CFStringGetCString(value,text,length,kCFStringEncodingUTF8)){free(text);text=NULL;}
        }
    }
    if(value)CFRelease(value);
    return text;
}
static int read_status(void) {
    char *text=string_property(CFSTR("ROAM_DIAGNOSTICS"));
    if(!text){fprintf(stderr,"Roaming diagnostics unavailable; verify Beta 7 DriverBuild\n");return 1;}
    snprintf(status,sizeof(status),"%s",text);free(text);return 0;
}
static unsigned long long number(const char *key) {
    size_t n=strlen(key);
    for(const char *p=status;*p;) {
        if(!strncmp(p,key,n)&&p[n]=='=')return strtoull(p+n+1,NULL,0);
        p=strchr(p,'\n');if(!p)break;++p;
    }
    return 0;
}
static int command(const char *name,const UInt8 *mac,int verbose) {
    if(geteuid()!=0){fprintf(stderr,"Use sudo for --%s\n",name);return 1;}
    CFMutableDictionaryRef dict=CFDictionaryCreateMutable(kCFAllocatorDefault,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFStringRef operation=CFStringCreateWithCString(kCFAllocatorDefault,name,kCFStringEncodingUTF8);
    if(!dict||!operation){if(dict)CFRelease(dict);if(operation)CFRelease(operation);return 1;}
    CFDictionarySetValue(dict,CFSTR("RoamCommand"),operation);CFRelease(operation);
    if(mac) {
        CFDataRef address=CFDataCreate(kCFAllocatorDefault,mac,6);
        if(!address){CFRelease(dict);return 1;}
        CFDictionarySetValue(dict,CFSTR("RoamToBSSID"),address);CFRelease(address);
    }
    kern_return_t result=IORegistryEntrySetCFProperties(service,dict);CFRelease(dict);
    if(verbose || result!=KERN_SUCCESS) {
        printf("%s result: 0x%08x (%s)\n",name,(unsigned)result,result==KERN_SUCCESS?"accepted":"rejected");
        if(!read_status())fputs(status,stdout);
    }
    return result==KERN_SUCCESS?0:1;
}
static int snapshot(void) {
    if(geteuid()==0 && command("snapshot",NULL,0))return 1;
    return read_status();
}
static int parse_mac(const char *arg,UInt8 mac[6]) {
    unsigned v[6];int consumed=0;
    if(strlen(arg)!=17 || sscanf(arg,"%2x:%2x:%2x:%2x:%2x:%2x%n",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5],&consumed)!=6 || consumed!=17)return 1;
    for(unsigned i=0;i<6;++i) {
        for(unsigned j=0;j<2;++j){char c=arg[3*i+j];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')))return 1;}
        mac[i]=(UInt8)v[i];
    }
    return 0;
}
static int field(const char *key,char *out,size_t capacity) {
    size_t n=strlen(key);
    for(const char *p=status;*p;) {
        if(!strncmp(p,key,n)&&p[n]=='=') {
            const char *value=p+n+1;size_t length=strcspn(value,"\n");
            if(length>=capacity)return 1;
            memcpy(out,value,length);out[length]=0;return 0;
        }
        p=strchr(p,'\n');if(!p)break;++p;
    }
    return 1;
}
static int aps(void) {
    if(snapshot())return 1;
    char *p=status;
    while(*p) {
        char *end=strchr(p,'\n');size_t n=end?(size_t)(end-p):strlen(p);
        if(!strncmp(p,"ap[",3)||!strncmp(p,"aps_listed=",11)||!strncmp(p,"current_bssid=",14)||!strncmp(p,"recommended_bssid=",18))
            printf("%.*s\n",(int)n,p);
        if(!end)break;p=end+1;
    }
    return 0;
}
static int neighbors(void) {
    CFTypeRef value=IORegistryEntryCreateCFProperty(service,CFSTR("ROAM_K_CANDIDATES"),kCFAllocatorDefault,0);
    int found=0;
    if(value && CFGetTypeID(value)==CFDataGetTypeID()) {
        CFDataRef data=(CFDataRef)value;const UInt8 *p=CFDataGetBytePtr(data);CFIndex n=CFDataGetLength(data);
        for(CFIndex i=0;i+6<=n;i+=6){printf("%02x:%02x:%02x:%02x:%02x:%02x\n",p[i],p[i+1],p[i+2],p[i+3],p[i+4],p[i+5]);found=1;}
    }
    if(value)CFRelease(value);
    if(!found)fprintf(stderr,"No fresh Neighbor Report candidates. Use --discover and --aps for actual scan results.\n");
    return found?0:1;
}
static int refresh(void) {
    if(snapshot())return 1;
    unsigned long long before=number("neighbor_responses");
    if(command("refresh",NULL,1))return 1;
    for(unsigned i=0;i<48;++i) {
        if(snapshot())return 1;
        if(!number("neighbor_pending")) {
            fputs(status,stdout);
            if(number("neighbor_responses")<=before){fprintf(stderr,"No accepted reply for this refresh\n");return 1;}
            return neighbors();
        }
        usleep(250000);
    }
    fprintf(stderr,"Refresh wait expired (12 seconds); no switch requested\n");fputs(status,stdout);return 1;
}
static int wait_scan(unsigned seconds) {
    for(unsigned i=0;i<seconds*4;++i) {
        if(snapshot())return 1;
        if(!number("scan_active")&&!number("scan_worker_pending")) {
            fputs(status,stdout);return number("scan_result")==2?0:1;
        }
        usleep(250000);
    }
    fprintf(stderr,"Scan wait expired (%u seconds); no switch requested\n",seconds);fputs(status,stdout);return 1;
}
static int scan(const UInt8 mac[6]) {
    if(command("scan",mac,1))return 1;
    return wait_scan(8);
}
static int discover(void) {
    if(snapshot())return 1;
    char engine[64];
    if(!field("scan_engine",engine,sizeof(engine))&&!strcmp(engine,"roam-discovery")&&
       number("scan_result")==2&&!number("scan_worker_pending")&&number("scan_completed_age_ms")<5000) {
        puts("Reusing the completed discovery from the last 5 seconds");return aps();
    }
    if(command("discover",NULL,1)||wait_scan(30))return 1;
    return aps();
}
static int best(int doRoam) {
    if(doRoam&&discover())return 1;
    if(command("select",NULL,1)||read_status())return 1;
    char chosen[18],current[18];UInt8 mac[6];
    if(field("recommended_bssid",chosen,sizeof(chosen))||field("current_bssid",current,sizeof(current))||parse_mac(chosen,mac))return 1;
    if(!strcmp(chosen,current)){puts("Current AP is preferred; no switch requested");return 0;}
    printf("Recommended target: %s\n",chosen);
    return doRoam?command("switch",mac,1):0;
}
static int report(void) {
    if(snapshot())return 1;
    char *build=string_property(CFSTR("DriverBuild"));
    printf("DriverBuild=%s\n",build?build:"unknown");free(build);fputs(status,stdout);
    char *log=string_property(CFSTR("DiagnosticLog"));
    if(log){puts("--- bounded driver log (may contain SSIDs/BSSIDs) ---");fputs(log,stdout);free(log);}
    return 0;
}
static int watch(unsigned seconds) {
    unsigned long long previous=~0ULL;
    long long previousBytes=-1;
    for(unsigned i=0;i<seconds;++i) {
        if(snapshot())return 1;
        unsigned long long now=number("now_ms");
        if(now!=previous){printf("--- sample %u ---\n%s",i,status);fflush(stdout);previous=now;}
        CFTypeRef count=IORegistryEntryCreateCFProperty(service,CFSTR("DiagnosticLogBytes"),kCFAllocatorDefault,0);
        long long bytes=-1;
        if(count && CFGetTypeID(count)==CFNumberGetTypeID())CFNumberGetValue(count,kCFNumberLongLongType,&bytes);
        if(count)CFRelease(count);
        if(previousBytes>=0 && bytes>previousBytes) {
            char *log=string_property(CFSTR("DiagnosticLog"));
            if(log) {
                size_t n=strlen(log);unsigned long long delta=(unsigned long long)(bytes-previousBytes);
                if(delta>n)puts("--- driver ring wrapped; some events were lost ---");
                puts("--- new driver events ---");fputs(log+n-(delta<n?(size_t)delta:n),stdout);free(log);fflush(stdout);
            }
        }
        if(bytes>=0)previousBytes=bytes;
        sleep(1);
    }
    return 0;
}
static void usage(void) {
    puts("rtw88-roam [--aps | --neighbors | --status | --report | --watch [1..3600]]\n"
         "sudo rtw88-roam --discover          (bounded 2.4/5 GHz scan; DFS passive)\n"
         "sudo rtw88-roam --best              (recommend from fresh scan cache)\n"
         "sudo rtw88-roam --roam-best         (discover + 5 GHz priority + switch if useful)\n"
         "sudo rtw88-roam --refresh\n"
         "sudo rtw88-roam --check BSSID       (preflight only)\n"
         "sudo rtw88-roam --scan BSSID        (one known channel; DFS passive)\n"
         "sudo rtw88-roam --prepare BSSID     (discover + check, no switch)\n"
         "sudo rtw88-roam --roam BSSID        (discover + switch to explicit target)\n"
         "sudo rtw88-roam BSSID               (switch using existing data)\n"
         "sudo rtw88-roam --log-level off|normal|verbose\n"
         "Acceptance/local keys do not prove AP acceptance or working IP traffic.");
}
int main(int argc,char **argv) {
    if(argc>3){usage();return 2;}
    if(argc==2&&!strcmp(argv[1],"--help")){usage();return 0;}
    service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("AirPortRTW"));
    if(!service){fprintf(stderr,"AirPortRTW service not found\n");return 1;}
    int result=2;
    if(argc==1 || (argc==2&&!strcmp(argv[1],"--neighbors")))result=neighbors();
    else if(argc==2&&!strcmp(argv[1],"--aps"))result=aps();
    else if(argc==2&&!strcmp(argv[1],"--discover"))result=discover();
    else if(argc==2&&!strcmp(argv[1],"--best"))result=best(0);
    else if(argc==2&&!strcmp(argv[1],"--roam-best"))result=best(1);
    else if(argc==2&&!strcmp(argv[1],"--status")){result=snapshot();if(!result)fputs(status,stdout);}
    else if(argc==2&&!strcmp(argv[1],"--report"))result=report();
    else if(argc==2&&!strcmp(argv[1],"--refresh"))result=refresh();
    else if(argc>=2&&!strcmp(argv[1],"--watch")) {
        char *end=NULL;unsigned long duration=argc==3?strtoul(argv[2],&end,10):60;
        if(duration>=1&&duration<=3600&&(argc==2||(*argv[2]&&!end[0])))result=watch((unsigned)duration);
    } else if(argc==3&&!strcmp(argv[1],"--log-level")) {
        const char *name=!strcmp(argv[2],"off")?"log-off":!strcmp(argv[2],"normal")?"log-normal":!strcmp(argv[2],"verbose")?"log-verbose":NULL;
        if(name)result=command(name,NULL,1);
    } else {
        UInt8 mac[6];const char *address=argc==3?argv[2]:argv[1];
        if(!parse_mac(address,mac)) {
            if(argc==2)result=command("switch",mac,1);
            else if(!strcmp(argv[1],"--check"))result=command("check",mac,1);
            else if(!strcmp(argv[1],"--scan"))result=scan(mac);
            else if(!strcmp(argv[1],"--prepare")||!strcmp(argv[1],"--roam")) {
                result=discover();
                if(!result)result=command(!strcmp(argv[1],"--prepare")?"check":"switch",mac,1);
            }
        }
    }
    if(result==2)usage();IOObjectRelease(service);return result;
}
