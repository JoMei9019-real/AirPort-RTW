#!/usr/bin/env python3
"""Beta 4 source contracts: private-MAC routing and isolated BT coexistence."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
def src(path):
    return (root / path).read_text()

h = src("src/kext/AirPortRTW.hpp")
c = src("src/kext/AirPortRTW.cpp")
iface = src("src/kext/RTW88IEEE80211.cpp")
compat = src("src/compat/rtw88_compat.c")
workflow = src(".github/workflows/native-build.yml")

assert "static_assert(sizeof(RTW88PrivateMACData) == 28" in h
assert "handlePrivateMACRequest" in c
assert "request->req_len != sizeof(payload)" in c
assert "copyin((user_addr_t)request->req_data" in c
assert "copyout(&payload, (user_addr_t)request->req_data" in c
assert "if (privateMACBridge && len != sizeof(RTW88PrivateMACData))" in c
for source in ("legacy-ioctl", "legacy-split-get", "skywalk-split-get",
               "legacy-split-set", "skywalk-split-set"):
    assert source in c, source
for p in ("STA_PRIVATE_MAC_SET_SEEN", "STA_PRIVATE_MAC_GET_SEEN",
          "STA_PRIVATE_MAC_LAST_RET"):
    assert p in c
assert "payload.enabled ? payload.timeout_seconds : 0" in c
assert "_ieee80211->getPermanentMACAddress(target)" in c
assert "getPermanentMACAddress(uint8_t *mac)" in iface
assert "rtwdev->coex.stat.wl_under_ips" in compat
assert "rtwdev->coex.stat.wl_under_lps" in compat
assert "rtw88_disable_watchdog_work = true" in compat
assert "rtw_coex_wl_status_check(rtwdev)" in compat
assert "rtw_coex_query_bt_hid_list(rtwdev)" in compat
assert "rtw_coex_active_query_bt_info(rtwdev)" in compat
assert "cancel_delayed_work_sync(&g_coex_maintenance_work)" in compat
assert "rtw88_coex_maintenance_worker" in compat
assert "1.3.0-beta.4" in workflow
assert "actions/upload-artifact@v4" in workflow
assert "publish:" not in workflow
print("PASS: Beta4 private-MAC ingress, BT coexistence maintenance, artifact-only workflow")
