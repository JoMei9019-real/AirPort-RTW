"""Replay the pinned Owly iPhone traces through AirPortRTW's production parser."""
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

captures = Path(sys.argv[1])
include = Path(__file__).resolve().parents[1] / "src/kext"
expected = {"discovery": (296, 101, 0), "receive": (312, 190, 1986), "send": (97, 466, 137)}
driver = r"""
#include "RTW88AWDLProtocol.hpp"
#include <cstdio>
int main() {
    unsigned psf = 0, mif = 0, ipv6 = 0;
    unsigned char header[3], frame[RTW88AWDL::MaxFrame];
    while (std::fread(header, 1, 3, stdin) == 3) {
        size_t size = RTW88AWDL::le16(header + 1);
        if (size > sizeof(frame) || std::fread(frame, 1, size, stdin) != size) return 1;
        if (header[0] == 0) {
            RTW88AWDL::Action action;
            if (!RTW88AWDL::parseAction(frame, size, action)) return 2;
            if (action.subtype == 3) ++mif;
            else ++psf;
        } else {
            uint16_t type;
            if (!RTW88AWDL::dataPayload(frame, size, type) || type != 0x86dd) return 3;
            ++ipv6;
        }
    }
    std::printf("%u %u %u", psf, mif, ipv6);
}
"""


def peer_records(path):
    peer, = re.findall(r'^peers = \["([0-9a-f:]{17})"\]$', path.with_suffix(".toml").read_text(), re.M)
    source = bytes.fromhex(peer.replace(":", ""))
    with path.open("rb") as capture:
        global_header = capture.read(24)
        assert global_header[:4] == bytes.fromhex("d4c3b2a1")
        assert struct.unpack_from("<I", global_header, 20)[0] == 127  # radiotap
        while header := capture.read(16):
            _, _, size, original = struct.unpack("<4I", header)
            packet = capture.read(size)
            assert len(packet) == size == original
            frame = packet[struct.unpack_from("<H", packet, 2)[0]:]
            if frame[10:16] != source:
                continue
            if frame[0] == 0xd0 and frame[24:30] == bytes.fromhex("7f0017f20810"):
                kind, payload = 0, frame
            elif frame[0] & 12 == 8 and frame[16:22] == bytes.fromhex("002500ff9473"):
                qos = bool(frame[0] & 128)
                offset = 24 + 6 * ((frame[1] & 3) == 3) + 2 * qos + 4 * (qos and bool(frame[1] & 128))
                kind, payload = 1, frame[offset:]
            else:
                continue
            yield struct.pack("<BH", kind, len(payload)) + payload


with tempfile.TemporaryDirectory() as tmp:
    binary = Path(tmp) / "replay"
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", "-I", str(include),
                    "-x", "c++", "-", "-o", str(binary)], input=driver, text=True, check=True)
    for session, counts in expected.items():
        path = captures / f"{session}-ios26.x-mt7925e-ch44-1.pcap"
        result = subprocess.check_output([str(binary)], input=b"".join(peer_records(path)))
        actual = tuple(map(int, result.split()))
        assert actual == counts, (session, actual, counts)
        print(f"PASS {session}: PSF={actual[0]}, MIF={actual[1]}, IPv6={actual[2]}")
