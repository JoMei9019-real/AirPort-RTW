#!/usr/bin/env python3
"""Check keyless Sequoia association handling without relaxing secured joins."""
from pathlib import Path
import subprocess, tempfile, os

root=Path(__file__).resolve().parents[1]
source=r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include "RTW88AssocWire.hpp"
static void write32(uint8_t*p,unsigned offset,uint32_t n) {
    for(unsigned i=0;i<4;++i)p[offset+i]=(uint8_t)(n>>(8*i));
}
static void request(uint8_t*p,uint32_t upper,uint32_t keyVersion,uint32_t keyLength,uint32_t cipher) {
    memset(p,0,140);
    write32(p,0,1);write32(p,4,2);write32(p,8,1);
    write32(p,12,upper);write32(p,16,4);memcpy(p+20,"test",4);
    write32(p,60,keyVersion);write32(p,64,keyLength);write32(p,68,cipher);
}
int main() {
    uint8_t wire[140]={};RTW88AssocWire::Personal d={};
    request(wire,0,0,0,0);assert(RTW88AssocWire::decode(wire,140,d));
    assert(d.upper==0&&d.keyLength==0&&d.cipher==0);
    request(wire,0,1,0,0);assert(RTW88AssocWire::decode(wire,140,d));
    request(wire,8,0,32,6);assert(!RTW88AssocWire::decode(wire,140,d));
    request(wire,8,1,32,6);assert(RTW88AssocWire::decode(wire,140,d));
    request(wire,0,0,1,0);assert(!RTW88AssocWire::decode(wire,140,d));
    request(wire,0,0,0,10);assert(!RTW88AssocWire::decode(wire,140,d));
}
'''
with tempfile.TemporaryDirectory() as d:
    src=Path(d)/'test.cpp';exe=Path(d)/'test';src.write_text(source)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-Wall','-Wextra','-Werror','-I'+str(root/'src/kext'),str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
print('PASS: Beta 3 open-network keyless association and secured regression')
