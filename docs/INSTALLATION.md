> For the experimental 1.2.0 Beta 5 menu test, follow
> [the beta instructions](../RELEASE_1_2_0_BETA_5.md). The instructions below
> describe the stable 1.1.0 setup and its legacy Wi-Fi dependencies.

# Installation with OpenCore

AirPort-RTW targets x86_64 Hackintosh systems using the Ventura-era Apple Wi-Fi
interface. The driver does not replace your complete EFI configuration.

## Before you start

1. Check your Wi-Fi card's PCI device ID against the table in the README.
   A matching Realtek brand name alone is not enough.
2. Download the prebuilt `AirPortRTW.kext` from the intended release. GitHub's
   **Source code** archives are for developers and do not contain a ready-to-use build.
3. Back up your working EFI and keep a bootable recovery copy.
4. Find the EFI partition used by OpenCore. Your kexts belong in
   `EFI/OC/Kexts/`; they are enabled in `EFI/OC/config.plist`.

## macOS Ventura (13)

Ventura already includes the Apple Wi-Fi components this driver targets.

1. Copy `AirPortRTW.kext` to `EFI/OC/Kexts/`.
2. Add an enabled entry for it under OpenCore **Kernel → Add**. If you use a
   snapshot tool, review the result and check that no duplicate entry was created.
3. Keep the system's `com.apple.iokit.IOSkywalkFamily` enabled. Do not add a
   **Kernel → Block** entry for it for this Ventura setup.
4. Do not inject the restored `IOSkywalkFamily.kext` or
   `IO80211FamilyLegacy.kext` used by the Sonoma-and-newer setup.
5. Disable the older Feixiao `rtw88.kext` and any duplicate AirPortRTW build.
6. Reboot and connect using the macOS Wi-Fi menu.

Lilu or AMFIPass may be needed by other parts of your EFI, but they are not
part of this Ventura-specific AirPort-RTW dependency chain.

## macOS Sonoma (14), Sequoia (15) and Tahoe (26)

These systems need a compatible restored legacy Apple Wi-Fi stack in addition
to AirPortRTW. An AirPortRTW update alone does not install those components.

The relevant files are available in
[OpenCore Legacy Patcher's Wi-Fi payloads](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/main/payloads/Kexts/Wifi).
Choose versions compatible with your macOS release. The payloads are distributed
as archives; extract the actual kext bundles before adding them to OpenCore.

The intended enabled **Kernel → Add** order is:

1. `Lilu.kext`
2. `AMFIPass.kext`
3. `IOSkywalkFamily.kext`
4. `IO80211FamilyLegacy.kext`
5. `AirPortRTW.kext`

Block the system's `com.apple.iokit.IOSkywalkFamily` under **Kernel → Block**
using Strategy `Exclude`, restricted to the Darwin versions for which you use
the replacement. Configure `SecureBootModel` compatibly with the restored stack.
Do not copy block entries or version limits from an unrelated EFI without
checking them.

`IO80211ElCap` and `corecaptureElCap` are not required for this setup.
Do not load the old Feixiao `rtw88.kext` alongside AirPortRTW.

If Wi-Fi already works with AirPortRTW on your macOS version, an ordinary driver
update usually means replacing its kext while retaining the working dependency
configuration. Recheck compatibility when updating macOS itself.

## Verify the installation

After rebooting, run:

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

A result shows the attached driver's build. If there is no result, first check
the PCI ID, enabled OpenCore entry, duplicate drivers and required Apple Wi-Fi
components. Then test Wi-Fi toggling, a WPA2 connection, Internet access, and
sleep/wake. A successful boot alone is not a complete compatibility test.

## Monterey (12) and earlier

These are not validated targets. The Ventura instructions should not be
assumed to work unchanged on older releases.
