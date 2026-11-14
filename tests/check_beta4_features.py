#!/usr/bin/env python3
"""Keep the Bluetooth maintenance and artifact-only build contracts."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
iface = (root / "src/kext/RTW88IEEE80211.cpp").read_text()
compat = (root / "src/compat/rtw88_compat.c").read_text()
workflow = (root / ".github/workflows/native-build.yml").read_text()

assert "rtwdev->coex.stat.wl_under_ips" in compat
assert "rtwdev->coex.stat.wl_under_lps" in compat
assert "rtw88_disable_watchdog_work = true" in compat
assert "rtw_coex_wl_status_check(rtwdev)" in compat
assert "rtw_coex_query_bt_hid_list(rtwdev)" in compat
assert "rtw_coex_active_query_bt_info(rtwdev)" in compat
assert "cancel_delayed_work_sync(&g_coex_maintenance_work)" in compat
assert "rtw88_coex_maintenance_worker" in compat
assert "rtw88_coex_maintenance_start();" in iface
stop = iface[iface.index("void RTW88IEEE80211::stop()"):]
assert stop.index("rtw88_coex_maintenance_stop();") < stop.index("rtw_pci_remove(_pcidev)")
assert "1.3.0-beta.7" in workflow
assert "actions/upload-artifact@v4" in workflow
assert "publish:" not in workflow
print("PASS: isolated BT coexistence maintenance, drain before PCI teardown, artifact-only workflow")
