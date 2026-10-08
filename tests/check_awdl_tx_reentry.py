#!/usr/bin/env python3
"""Exercise synchronous callback recursion and competing queue owners."""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'src/kext/AirPortRTWAWDL.cpp').read_text()
start = source.index('void AirPortRTW::drainAWDLTxPackets(')
end = source.index('\nvoid ', start + 1)
drain = source[start:end]
assert '->isOutputFlowControlled(' not in source
assert drain.index('RTW88TxDrainGuard drainGuard') < drain.index('vif->getInterfaceRole()')
assert drain.index('if (!drainGuard.acquired())') < drain.index('vif->dequeueOutputPacketsWithServiceClass(')

test = r'''
#include "RTW88TxDrainGuard.hpp"
#include <cassert>
#include <atomic>
#include <thread>
#include <iostream>
bool active = false;
unsigned drains = 0, rejected = 0, packets = 1;
void requestPacketTx() {
    RTW88TxDrainGuard guard(&active);
    if (!guard.acquired()) { ++rejected; return; }
    ++drains;
    // Native outputStart synchronously calls back while the first drain owns
    // its queue. The nested call must leave packet ownership with this call.
    requestPacketTx();
    if (packets) --packets;
}
int main() {
    requestPacketTx();
    assert(drains == 1 && rejected == 1 && packets == 0 && !active);
    packets = 1;
    requestPacketTx();
    assert(drains == 2 && rejected == 2 && packets == 0 && !active);
    std::atomic<bool> entered{false}, release{false};
    std::thread owner([&] {
        RTW88TxDrainGuard guard(&active);
        assert(guard.acquired());
        entered.store(true);
        while (!release.load()) std::this_thread::yield();
    });
    while (!entered.load()) std::this_thread::yield();
    { RTW88TxDrainGuard competing(&active); assert(!competing.acquired()); }
    release.store(true); owner.join();
    { RTW88TxDrainGuard later(&active); assert(later.acquired()); }
    assert(!active);
    // Destruction also releases ownership on an early return.
    auto early = [] { RTW88TxDrainGuard guard(&active); assert(guard.acquired()); return; };
    early(); assert(!active);
    std::cout << "PASS: synchronous recursion stops, packets retain one owner, competing drain rejected, later drain and early return release\n";
}
'''
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory)
    (path / 'test.cpp').write_text(test)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-pthread',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(root / 'src/kext'), str(path / 'test.cpp'),
                    '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
