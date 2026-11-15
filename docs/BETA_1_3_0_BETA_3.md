# AirPort-RTW 1.3.0 Beta 3 (test build only)

Branch: `1.0.0-beta`. This development build is not a GitHub Release.

## Changes since Beta 2
- Accept key-version 0 only for genuinely keyless open networks on macOS Sequoia; secure join validation remains unchanged.
- Report 2.4 GHz HT/N rather than AC when an AP's IEs include VHT despite its 2.4 GHz channel.
- Expose the connected station's live firmware C2H rate-adaptation report (MCS, spatial streams, bandwidth and guard interval).
- Report current TX PHY rate from firmware instead of the highest legacy rate advertised by the AP.
- Preserve Beta 2 coexistence association-start/finish handling and the Wi-Fi startup-priority experiment.

## Deferred from the submitted community patch
- Selector 238 private-MAC Fixed/Rotate/Off semantics: undocumented payload, requires device-level ABI tests and safe MAC rotation lifecycle handling.
- SNR-based noise: the RTL8821C dependency patch and measurement calibration need separate review.
- iPhone Personal Hotspot: no verified fix was included in the community patch.

## Test and installation notes
GitHub Actions should upload `AirPortRTW-1.3.0-beta.3.zip` only when regression checks, macOS compilation, binary verification and packaging all succeed. The beta workflow contains no publish job. A successful CI build does not establish Bluetooth/RF compatibility or hardware stability.

Run tests with a backed-up EFI, and verify open-network connection, WPA2/WPA3, 2.4/5 GHz roaming, MCS/NSS rates, Bluetooth audio/HID during scanning, sleep/wake and sustained bidirectional transfers. Do not install two AirPort-RTW drivers simultaneously.

Community patch reference: https://github.com/JoMei9019-real/AirPort-RTW/issues/6
