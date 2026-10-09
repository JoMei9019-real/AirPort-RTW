# 1.0.2 Beta 4: experimental RTL8814AE

Built on 1.0.0-beta / Beta 3, with all deferred RX, AWDL power fencing,
link-event ABI and wake reconnect changes retained.

## Added

- RTL8814AE PCIe match: vendor 10ec, device 8813 (also called RTL8813AE).
- RTL8814A hardware core, RF/power tables and PCIe frontend compiled in.
- Native backend chip selection and hardware name publication.
- Embedded RTL8814A firmware with a pinned download and SHA-256 check.
- Reviewed rtw88-stable revision pinned for reproducible chip integration.
- Build checks for the linked chip specification, firmware and PCI personality.

RTL8814AE support is experimental and has not been tested on physical hardware.
RTL8812AE is deferred; this build does not advertise its PCI ID.

## Sleep and diagnostics

No speculative DarkWake patch is included. The reported repeated DarkWake
pattern persisted in the comparison test with AirPortRTW unloaded.
That does not prove that every sleep issue is resolved. Long/deep sleep remains
unverified. The CoreWiFi BSSID_CHANGED length warning is not claimed fixed.
AWDL/AirDrop work from the 2.0.0 beta branch is not merged into this branch.

## Hardware test

1. Replace the previous AirPortRTW.kext, keep a bootable fallback EFI, reboot.
2. Verify DriverBuild is 1.0.2-beta.4-rtl8814ae and the controller attaches to
   10ec:8813 on an RTL8814AE card.
3. Scan and connect on both 2.4 and 5 GHz; test bidirectional traffic.
4. Toggle Wi-Fi off/on, switch networks and verify automatic reconnect.
5. Test short and longer sleep; capture diagnostics immediately after wake.
6. Recheck existing RTL8821CE/RTL8822BE/RTL8822CE hardware for regressions.

```sh
ioreg -l -w0 -r -c AirPortRTW > ~/Desktop/airport-beta4-ioreg.txt
sudo log show --last 15m --style compact --predicate '(process == "kernel" AND eventMessage CONTAINS[c] "AirPortRTW") OR process == "airportd" OR process == "powerd"' > ~/Desktop/airport-beta4-wake.log
pmset -g log > ~/Desktop/airport-beta4-pmset.txt
```
