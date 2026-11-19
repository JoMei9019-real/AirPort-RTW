"""Verify Legacy AWDL request budgets and ABI for every queue mask."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    binary = Path(tmp) / "peer-tx"
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", "-Wall", "-Wextra",
                    "-Werror", "-I", str(root / "src/kext"), "-x", "c++", "-", "-o", str(binary)],
                   input=r"""
#include "RTW88AWDLPeerTx.hpp"
#include <cassert>
int main() {
    for (unsigned mask = 0; mask < 64; ++mask) {
        for (unsigned slots = 0; slots <= 128; ++slots) {
            RTW88AWDL::PeerTxRequest<void *> r{};
            r.prepare(mask, slots);
            unsigned sum = 0;
            for (unsigned i = 0; i < 8; ++i) {
                assert(!r.heads[i] && r.counts[i] <= 8);
                if (i >= 4 || !(mask & (1U << i))) assert(!r.counts[i]);
                sum += r.counts[i];
            }
            assert(r.flags == 0 && r.mask == (mask & 15));
            assert(r.unicast == sum && r.total == sum + r.multicast);
            assert(r.total <= slots && r.total <= 40);
            assert(bool(r.total) == bool(slots && (mask & 31)));
            assert(bool(r.multicast) == bool(slots && (mask & 16)));
        }
    }
}
""", text=True, check=True)
    subprocess.run([str(binary)], check=True)
print("PASS: Legacy peer queue mask, ABI, multicast and queue capacity")
