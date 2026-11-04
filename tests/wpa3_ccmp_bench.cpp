// Diagnostic only: host CPU throughput is not a Wi-Fi link measurement.
#include "../src/kext/RTW88WPA3.hpp"
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <vector>
int main(int argc,char**argv){
 unsigned frames=argc>1?unsigned(strtoul(argv[1],nullptr,10)):2000;
 uint8_t f[26+8+1500+8]={0x88,0x41},key[16]={};f[4]=2;f[10]=4;f[16]=6;f[29]=0x20;
 std::vector<uint8_t> packets(size_t(frames)*sizeof(f));
 auto t=std::clock();
 for(unsigned i=0;i<frames;++i){memset(f+34,0x5a,1500);if(!RTW88WPA3::ccmp(f,sizeof(f),key,uint64_t(i)+1,true))return 1;memcpy(packets.data()+size_t(i)*sizeof(f),f,sizeof(f));}
 double seconds=double(std::clock()-t)/CLOCKS_PER_SEC;
 printf("CCMP encrypt: %.2f Mbit/s (%u x 1500 bytes, %.3f s)\n",frames*1500.*8/seconds/1e6,frames,seconds);
 t=std::clock();
 for(unsigned i=0;i<frames;++i){if(!RTW88WPA3::ccmp(packets.data()+size_t(i)*sizeof(f),sizeof(f),key,uint64_t(i)+1,false))return 1;}
 seconds=double(std::clock()-t)/CLOCKS_PER_SEC;
 printf("CCMP decrypt/authenticate workload: %.2f Mbit/s (%u x 1500 bytes, %.3f s)\n",frames*1500.*8/seconds/1e6,frames,seconds);
}
