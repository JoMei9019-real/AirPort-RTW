# Notice

AirPort-RTW is distributed under the GNU General Public License, version 2
(`LICENSE`). This file records the license notices that the GPL requires to
travel with the source.

## Derived source

AirPort-RTW is a derived work of GPL-2.0 licensed source:

- the AirPort_RTW88 / RTL88WiFi native IO80211 work used as the macOS frontend reference (GPLv2);
- Feixiao and the rtw88 macOS port it was built on;
- the Linux kernel `rtw88` driver, dual licensed GPL-2.0 OR BSD-3-Clause
  (`driver/rtw88-stable/COPYING`).

Individual source files keep their SPDX license identifiers and copyright
notices. Files changed for AirPort-RTW carry a "Modified by X1REN41L" line with
the date; the full change history is in the Git log and `CHANGELOG.md`.

## Separately licensed parts

- Kernel SDK headers in `driver/AirPort-RTW/MacKernelSDK/` keep their own
  notices and `LICENSE.txt`.
- Realtek firmware in `driver/AirPort-RTW/firmware/` keeps its original notices
  (`driver/AirPort-RTW/firmware/README`).
- `Kexts/AMFIPass.kext`, `Kexts/IOSkywalkFamily.kext` and
  `Kexts/IO80211FamilyLegacy.kext` are separate third-party or Apple binaries
  shipped for convenience. They are not AirPort-RTW code and are not relicensed
  by this repository.

The combined AirPort-RTW driver is distributed under GPLv2. This does not
relicense the SDK, the firmware or the bundled dependency kexts.
