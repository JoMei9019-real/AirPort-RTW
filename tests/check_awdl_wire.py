#!/usr/bin/env python3
"""Exercise the production AWDL data envelopes and Apple RX TLV filter."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

include = Path(__file__).resolve().parents[1] / 'src/kext'
fixture = r'''
#include <cassert>
#include "RTW88AWDLProtocol.hpp"
#include "../compat/rtw88_data_header.h"

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

    uint8_t wrapped[30] = {0xaa, 0xaa, 3, 0, 0, 0, 0, 20};
    memcpy(wrapped + 8, envelope, sizeof(envelope));
    const uint8_t *msdu = wrapped;
    size_t msduLength = sizeof(wrapped);
    assert(unwrapLengthPrefixedMSDU(msdu, msduLength));
    assert(msdu == wrapped + 8 && msduLength == 20); // excludes two padding bytes
    assert(dataPayload(msdu, msduLength, type) && type == 0x86dd);

    Clock peerClock{};
    peerClock.epochUS = 1024;
    peerClock.periodTU = 16;
    peerClock.presence = 4;
    Sequence peerChannels{};
    peerChannels.count = 2;
    peerChannels.stride = 4;
    peerChannels.channel[1] = 44;

    auto beforeChannelCheck = window(peerClock, peerChannels, 8 * 1024);
    auto afterChannelCheck = window(peerClock, peerChannels, 9 * 1024);
    assert(!insideGuard(beforeChannelCheck));
    assert(!useHomeChannelForEmptySlot(beforeChannelCheck, 36, 44));
    assert(useHomeChannelForEmptySlot(beforeChannelCheck, 44, 44));
    assert(useHomeChannelForEmptySlot(afterChannelCheck, 44, 44));
    assert(beforeChannelCheck.channel == afterChannelCheck.channel);
    assert(insideGuard(afterChannelCheck) && multicastWindow(afterChannelCheck));

    auto explicitChannel = window(peerClock, peerChannels, 80 * 1024);
    assert(explicitChannel.channel == 44);
    assert(!useHomeChannelForEmptySlot(explicitChannel, 36, 36));
    auto invalidWindow = window(peerClock, peerChannels, 0);
    assert(!useHomeChannelForEmptySlot(invalidWindow, 44, 44));
    assert(!unwrapLengthPrefixedMSDU(msdu, msduLength)); // direct SNAP

    // An ordered QoS data frame carries four HT Control bytes after QoS
    // Control. The same offsets are used by the production AWDL RX parser.
    uint8_t qosFrame[60] = {0x88, 0x80};
    memcpy(qosFrame + 26, "HTCT", 4);
    memcpy(qosFrame + 30, wrapped, sizeof(wrapped));
    const unsigned fc = qosFrame[0] | (unsigned(qosFrame[1]) << 8);
    const size_t headerLength = rtw88_data_header_length(fc);
    assert(rtw88_has_ht_control(fc) && rtw88_qos_offset(fc) == 24 && headerLength == 30);
    const uint8_t *oldOffset = qosFrame + 26;
    size_t oldLength = sizeof(qosFrame) - 26;
    assert(!unwrapLengthPrefixedMSDU(oldOffset, oldLength));
    msdu = qosFrame + headerLength;
    msduLength = sizeof(qosFrame) - headerLength;
    assert(unwrapLengthPrefixedMSDU(msdu, msduLength));
    assert(dataPayload(msdu, msduLength, type) && type == 0x86dd);

    msdu = wrapped;
    msduLength = sizeof(wrapped);
    wrapped[7] = 23;
    assert(!unwrapLengthPrefixedMSDU(msdu, msduLength));
    wrapped[7] = 15;
    assert(!unwrapLengthPrefixedMSDU(msdu, msduLength));
    wrapped[7] = 20;
    wrapped[16] = 0;
    assert(!unwrapLengthPrefixedMSDU(msdu, msduLength));
    assert(msdu == wrapped && msduLength == sizeof(wrapped));

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
print('PASS: AWDL TX formats, length-prefixed RX MSDUs and bounded Apple action RX TLV filtering')
