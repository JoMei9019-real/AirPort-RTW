# AirPort-RTW

AirPort-RTW is a native macOS IO80211 Wi-Fi driver project derived from the Feixiao rtw88 macOS port.

The goal is to keep Feixiao's Realtek/Linux rtw88 hardware core while replacing the user-controlled network frontend with a native macOS AirPort-style frontend based on IO80211FamilyLegacy and IOSkywalkFamily.

## First integrated target

This branch intentionally delivers the native stack as one larger test unit rather than many reboot-heavy intermediate builds:

- native macOS Wi-Fi interface / menu integration
- scanning
- association
- WPA/WPA2 path
- 2.4 / 5 GHz support
- link state and RX/TX integration
- power-management / sleep-wake hooks
- diagnostics and rtw88 control path retained where useful

Initial PCIe IDs:

- RTL8821CE: 10ec:c821, 10ec:b821
- RTL8822BE: 10ec:b822
- RTL8822CE: 10ec:c822, 10ec:c82f

RTL8812AE / RTL8814AE remain in the Feixiao lineage but are deliberately not enabled in this first native test build.

## Dependencies

Run:

```sh
./scripts/bootstrap-deps.sh
```

This checks out:

- AcidAnthera MacKernelSDK
- thegwchr rtw88-stable

The bootstrap script fetches the three required firmware blobs into `firmware/` reproducibly before building.

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

These releases require the restored legacy Apple Wi-Fi stack. The intended OpenCore load order is:

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

For the first real hardware test, use one reboot and validate the whole path:

1. confirm AirPortRTW attaches to the Realtek PCI device;
2. verify Wi-Fi appears in macOS;
3. scan and join a WPA2 or WPA2/WPA3-transition network;
4. test normal traffic on 2.4 and 5 GHz;
5. sleep and wake once;
6. switch networks once;
7. collect the diagnostic log if any step fails.

This branch is experimental kernel code. Keep a bootable fallback EFI.


## Lineage and licensing

AirPort-RTW starts from Feixiao and incorporates GPL-compatible native IO80211 work from the RTL88WiFi / AirPort_RTW88 lineage. See `NOTICE.md` and the retained SPDX/copyright notices in individual source files.
