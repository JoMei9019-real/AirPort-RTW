#!/usr/bin/env python3
"""Exercise the production AWDL TX envelope and Apple RX TLV filter."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

include = Path(__file__).resolve().parents[1] / 'src/kext'
fixture = r'''
#include <cassert>
#include "RTW88AWDLProtocol.hpp"

int main() {
    using namespace RTW88AWDL;
    uint16_t type = 0;
    size_t offset = 0;
    uint8_t packet[78] = {};
    packet[12] = 0x86;
    packet[13] = 0xdd;
    assert(txPayload(packet, 14, sizeof(packet), type, offset));
    assert(type == 0x86dd && offset == 14);

    const uint8_t envelope[] = {0xaa,0xaa,0x03,0x00,0x17,0xf2,0x08,0x00,
                                0x03,0x04,0x00,0x00,0x00,0x00,0x86,0xdd};
    packet[12] = 0;
    packet[13] = sizeof(packet) - 14;
    memcpy(packet + 14, envelope, sizeof(envelope));
    assert(txPayload(packet, 30, sizeof(packet), type, offset));
    assert(type == 0x86dd && offset == 30);
    assert(!txPayload(packet, 29, sizeof(packet), type, offset));
    assert(!txPayload(packet, 30, sizeof(packet) - 1, type, offset));
    packet[14] = 0;
    assert(!txPayload(packet, 30, sizeof(packet), type, offset));

    const uint8_t body[] = {
        0x7f, 0, 0x17, 0xf2, 8, 0x10, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 2, 0, 0xaa, 0xbb,
        4, 1, 0, 0x55,
        0x10, 1, 0, 0xcc,
        0, 0
    };
    uint8_t filtered[sizeof(body)] = {};
    assert(copyAppleActionBody(filtered, body, sizeof(body)) == 20);
    assert(memcmp(filtered, body, 16) == 0);
    assert(memcmp(filtered + 16, body + 21, 4) == 0);
    assert(copyAppleActionBody(filtered, body, 24) == 0);
    assert(copyAppleActionBody(filtered, body, 15) == 0);
}
'''
with TemporaryDirectory() as directory:
    source = Path(directory) / 'awdl.cpp'
    binary = Path(directory) / 'awdl'
    source.write_text(fixture)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-Wall', '-Wextra',
                    '-Werror', '-I', str(include), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: AWDL TX Ethernet/802.3 formats and bounded Apple action RX TLV filtering')
