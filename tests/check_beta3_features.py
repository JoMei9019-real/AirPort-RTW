#!/usr/bin/env python3
"""Beta 3 source-contract checks: live firmware RA report and channel PHY."""
from pathlib import Path
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
assert 'rtw88CurrentRate500Kbps(telemetry)' in controller
assert 'd->index = telemetry.mcs' in controller
assert 'd->nss = telemetry.nss' in controller
assert 'd->rate[0]=rate' in controller
assert 'hasVHT && b.channel > 14' in controller
assert '1.3.0-beta.6' in controller
assert 'd->index = 0; /* live TX-MCS export is not wired yet */' not in controller
# 433.5 Mbps VHT80 MCS9 one stream, short GI -> integer 500-kbit/s units
# 867 units are reported, yielding 433.5 Mbps from the UI representation.
assert '780,867' in controller
print('PASS: live firmware RA telemetry wiring, PHY band, Beta 6 version')
