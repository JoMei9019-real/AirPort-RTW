# AirPortRTW 1.0.2

Published from the 1.0.2 Beta 4 code on `1.0.0-beta` to `main`.
The final build identifies itself as `1.0.2-release`; the bundle and kmod
versions are `1.0.2`. No 2.0.0 beta feature changes are included.

## Changes since 1.0.1

- Bounded deferred RX processing and shutdown ordering to address the
  observed `flush_work` / `napi_stop` sleep-transition deadlock.
- AWDL power fencing: cancel timers, flush owned queues, reject late work
  while suspended, and resume only when the radio is actually powered.
- Wake scan/association cleanup and corrected native notifications for
  automatic reconnect, preserving a user-disabled Wi-Fi radio.
- Native LINK_CHANGED wire layout and link-status query corrections.
- Experimental RTL8814AE (`10ec:8813`) chip, table, PCI match and firmware
  integration, with a pinned core revision and verified firmware download.
- RX ownership, AWDL power and link/wake regression tests and native
  macOS x86_64 bundle checks.

## Remaining limitations

Uninterrupted long/deep sleep, standby and hibernation remain unverified.
The reported DarkWake pattern persisted without AirPortRTW loaded, so no
speculative driver workaround is included. The CoreWiFi BSSID_CHANGED
length warning is not claimed fixed. RTL8814AE requires physical hardware
testing; RTL8812AE, USB and SDIO are not enabled. AirDrop feature work
remains on the separate 2.0.0 beta branch.

## Installation and verification

Replace the existing AirPortRTW.kext in EFI/OC/Kexts, retain the applicable
legacy Wi-Fi dependencies described in the README, and reboot. Do not load
multiple AirPortRTW/rtw88 builds simultaneously.

Confirm DriverBuild is `1.0.2-release`, scan and connect on 2.4 and 5 GHz,
test traffic, Wi-Fi toggles, network switching and reconnect after wake.
Test short and longer sleep and collect logs immediately after waking:

```sh
ioreg -l -w0 -r -c AirPortRTW > ~/Desktop/airport-1.0.2-ioreg.txt
sudo log show --last 15m --style compact --predicate '(process == "kernel" AND eventMessage CONTAINS[c] "AirPortRTW") OR process == "airportd" OR process == "powerd"' > ~/Desktop/airport-1.0.2-wake.log
pmset -g log > ~/Desktop/airport-1.0.2-pmset.txt
```
