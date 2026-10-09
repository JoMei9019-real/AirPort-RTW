# AirPort-RTW

AirPort-RTW is a native macOS IO80211 Wi-Fi driver for Realtek PCIe cards, derived from the Feixiao rtw88 macOS port. It uses the Linux rtw88 hardware core with an AirPort frontend based on IO80211FamilyLegacy and IOSkywalkFamily.

## Version 1.0.2

Version 1.0.2 incorporates the changes tested through 1.0.2 Beta 4. It provides native Wi-Fi menu integration, scanning, association, WPA/WPA2, 2.4/5 GHz operation and sleep/wake handling.

### Changes since 1.0.1

- Deferred RX processing through a bounded queue to address the sleep shutdown deadlock observed in `flush_work` / `napi_stop`.
- AWDL timer and queue fencing during power transitions to prevent late RX/TX work and re-arming while suspended.
- Wake-state cleanup and corrected power/link notifications to improve automatic reconnect while preserving a user-disabled radio.
- Correct native `LINK_CHANGED` notification and link-status query layouts.
- Experimental RTL8814AE PCIe support, including the hardware core, tables and embedded firmware.
- Automated RX ownership, AWDL power and link/wake regression checks; firmware checksum and bundle checks.

See [1.0.2 release notes and testing](RELEASE_1_0_2.md).

## Supported PCIe IDs

| Chip | Vendor:device IDs | Status |
| --- | --- | --- |
| RTL8821CE | `10ec:c821`, `10ec:b821` | Existing support |
| RTL8822BE | `10ec:b822` | Existing support |
| RTL8822CE | `10ec:c822`, `10ec:c82f` | Existing support |
| RTL8814AE | `10ec:8813` | Experimental; physical hardware validation pending |

Some PCI tools identify RTL8814AE as RTL8813AE. RTL8812AE is not enabled; it requires a separate PCIe transport integration. USB and SDIO adapters are not supported by this project.

## Known limitations

- **Deep sleep is not guaranteed to work reliably on every system.** Version 1.0.2 addresses the observed driver shutdown deadlock, but uninterrupted long sleep, standby and hibernation still need hardware validation.
- In the reported comparison test, frequent DarkWakes persisted with AirPortRTW unloaded. No speculative driver fix for that pattern is included.
- The CoreWiFi `BSSID_CHANGED` length warning is not claimed fixed by this release.
- RTL8814AE support is experimental. A successful build does not establish hardware compatibility.
- AirDrop/AWDL feature development on `beta-2.0.0` is separate and has not been merged into this release. AWDL power fencing does not imply working AirDrop support.

## Dependencies

Run:

```sh
./scripts/bootstrap-deps.sh
```

This checks out:

- AcidAnthera MacKernelSDK
- thegwchr rtw88-stable at `d029a677c49266fad86750714eb5612becd134d3`

The bootstrap script fetches four required firmware blobs into `firmware/`. The RTL8814A download is pinned to a commit and checked against its SHA-256 hash.

## Build

```sh
make airport
```

Output:

```
build/out/AirPortRTW.kext
```

The project currently targets x86_64 Hackintosh systems and the Ventura IO80211FamilyLegacy ABI.

## OpenCore setup by macOS version

AirPort-RTW currently targets the Ventura-era IO80211 ABI. The OpenCore setup differs depending on the macOS version.

### macOS Ventura (13)

Ventura already ships the Apple Wi-Fi frameworks that AirPort-RTW targets. Do **not** inject the restored Sonoma+ legacy Wi-Fi stack on Ventura.

1. Copy `AirPortRTW.kext` to `EFI/OC/Kexts/`.
2. Add and enable `AirPortRTW.kext` under OpenCore `Kernel -> Add`.
3. Leave the stock `com.apple.iokit.IOSkywalkFamily` enabled. Do **not** add an OpenCore `Kernel -> Block` entry for it.
4. Do **not** add `IOSkywalkFamily.kext` or `IO80211FamilyLegacy.kext` from the Sonoma/Sequoia/Tahoe compatibility setup.
5. Do not load the old Feixiao `rtw88.kext` at the same time as AirPortRTW; both would match the same PCI device.
6. Reboot and verify that AirPortRTW attaches to the Realtek PCI device and that Wi-Fi appears in macOS.

Lilu and AMFIPass may still be present if your EFI needs them for other patches, but they are not part of the Ventura-specific AirPort-RTW dependency chain described above.

### macOS Sonoma / Sequoia / Tahoe

These releases require the restored legacy Apple Wi-Fi stack.

The required legacy Wi-Fi kexts can be found in the OpenCore Legacy Patcher repository:

[OpenCore-Legacy-Patcher / payloads / Kexts / Wifi](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/main/payloads/Kexts/Wifi)

For AirPort-RTW, the relevant kexts from that folder are:

- `IOSkywalkFamily.kext`
- `IO80211FamilyLegacy.kext`

You do **not** need `IO80211ElCap` or `corecaptureElCap` for the AirPort-RTW setup described here. Use versions that are compatible with your macOS release.

The intended OpenCore load order is:

1. Lilu
2. AMFIPass
3. IOSkywalkFamily
4. IO80211FamilyLegacy
5. AirPortRTW

Block the stock `com.apple.iokit.IOSkywalkFamily` using OpenCore `Kernel -> Block` with Strategy `Exclude` for the applicable Darwin versions. `SecureBootModel` must be configured compatibly with the restored legacy stack.

Do not load the old Feixiao `rtw88.kext` at the same time as AirPortRTW; both would match the same PCI device.

### macOS Monterey and earlier

Monterey and earlier releases are **not currently validated targets** for AirPort-RTW. The project is built around the Ventura IO80211 ABI, so the Ventura instructions should not be assumed to work unchanged on older releases. If support for an older release is added later, its required framework and OpenCore configuration will be documented here.


## Test plan

After replacing the kext and rebooting, validate the following:

1. confirm AirPortRTW attaches to the Realtek PCI device;
2. verify Wi-Fi appears in macOS;
3. scan and join a WPA2 or WPA2/WPA3-transition network;
4. test normal traffic on 2.4 and 5 GHz;
5. sleep and wake once;
6. switch networks once;
7. collect the diagnostic log if any step fails.

Keep a bootable fallback EFI when testing a new build, especially on experimental RTL8814AE hardware.


## Lineage and licensing

AirPort-RTW starts from Feixiao and incorporates GPL-compatible native IO80211 work from the RTL88WiFi / AirPort_RTW88 lineage. See `NOTICE.md` and the retained SPDX/copyright notices in individual source files.
