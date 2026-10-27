#include "../src/kext/RTW88WPA3AES.hpp"
#include <cassert>
#include <cstring>
#include <cstdio>
int main(){
    const uint8_t key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint8_t block[16]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t answer[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,4,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t out[16];RTW88WPA3::AES128 cipher(key);cipher.encrypt(block,out);assert(!memcmp(out,answer,16));
    uint32_t random=0x12345678;
    for(unsigned i=0;i<10000;++i){
        uint8_t k[16],in[16],expected[16];
        for(unsigned j=0;j<32;++j){random^=random<<13;random^=random>>17;random^=random<<5;(j<16?k[j]:in[j-16])=uint8_t(random);}
        rtw_sae_aes128_encrypt(k,in,expected);RTW88WPA3::AES128 aes(k);aes.encrypt(in,out);assert(!memcmp(out,expected,16));
        aes.encrypt(in,in);assert(!memcmp(in,expected,16));
        // Reusing a context must not mutate the schedule, including aliasing.
        aes.encrypt(block,out);rtw_sae_aes128_encrypt(k,block,expected);assert(!memcmp(out,expected,16));
    }
    puts("PASS: cached scalar AES FIPS-197 answer, 10,000 differential keys/blocks and in-place operation");
}
