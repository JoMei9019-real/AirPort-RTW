#!/usr/bin/env python3
"""Check live firmware RA wiring, channel PHY and current TX rate conversion."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

root=Path(__file__).resolve().parents[1]
compat=(root/'src/compat/rtw88_compat.c').read_text()
api=(root/'src/compat/rtw88_compat.h').read_text()
backend=(root/'src/kext/RTW88IEEE80211.cpp').read_text()
controller=(root/'src/kext/AirPortRTW.cpp').read_text()
for token in ('si->ra_report.bit_rate','si->ra_report.txrate.mcs',
              'si->ra_report.txrate.nss','si->ra_report.txrate.bw'):
    assert token in compat, token
assert 'rtw88_tx_rate_snapshot' in api
assert 'rtw88_get_tx_rate_snapshot(_sta, &rate)' in backend
assert 'rtw88CurrentTxRateMbps(telemetry)' in controller
assert 'd->index = telemetry.mcs' in controller
assert 'd->nss = telemetry.nss' in controller
assert 'd->rate[0]=rate' in controller
assert 'hasVHT && b.channel > 14' in controller
assert '1.3.0-beta.8' in controller
assert 'd->index = 0; /* live TX-MCS export is not wired yet */' not in controller

start = controller.index('static uint32_t rtw88CurrentTxRateMbps(')
convert_rate = controller[start:controller.index('\n}', start) + 2]
fixture = r'''
#include <cassert>
#include <cstdint>

namespace RTW88IEEE80211 {
struct RadioTelemetry {
    bool rateValid;
    uint32_t nss, mcs, bandwidth, rateFlags, legacyRate100kbps;
};
}

enum {
    RATE_INFO_FLAGS_SHORT_GI = 1, RATE_INFO_FLAGS_VHT_MCS = 2, RATE_INFO_FLAGS_MCS = 4,
    RATE_INFO_BW_40 = 40, RATE_INFO_BW_80 = 80,
};
''' + convert_rate + r'''
int main() {
    using RTW88IEEE80211::RadioTelemetry;
    RadioTelemetry report{true, 1, 0, 20, 0, 540};
    assert(rtw88CurrentTxRateMbps(report) == 54);
    report.legacyRate100kbps = 60;
    assert(rtw88CurrentTxRateMbps(report) == 6);
    report.legacyRate100kbps = 55;
    assert(rtw88CurrentTxRateMbps(report) == 5); // 5.5 Mbit/s CCK, integer field
    report.legacyRate100kbps = 0;
    assert(rtw88CurrentTxRateMbps(report) == 0);

    report = {true, 1, 7, 20, RATE_INFO_FLAGS_SHORT_GI | RATE_INFO_FLAGS_MCS, 0};
    assert(rtw88CurrentTxRateMbps(report) == 72);
    report.bandwidth = RATE_INFO_BW_40;
    assert(rtw88CurrentTxRateMbps(report) == 150);

    report = {true, 1, 9, RATE_INFO_BW_80, RATE_INFO_FLAGS_SHORT_GI | RATE_INFO_FLAGS_VHT_MCS, 0};
    assert(rtw88CurrentTxRateMbps(report) == 433);
    report.rateValid = false;
    assert(rtw88CurrentTxRateMbps(report) == 0);
}
'''
with TemporaryDirectory() as folder:
    source = Path(folder) / 'tx_rate.cpp'
    binary = Path(folder) / 'tx_rate'
    source.write_text(fixture)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

print('PASS: live firmware RA wiring, PHY band, and Legacy/HT/VHT TX rates in Mbit/s')
