# AirPort-RTW

A macOS Wi-Fi driver for supported **Realtek PCIe cards**. AirPort-RTW integrates
with the normal macOS Wi-Fi menu, so you can find and join networks without a
separate connection app. It is intended for x86_64 Hackintosh systems.

## Download

**Current stable release: [1.0.2](https://github.com/JoMei9019-real/AirPort-RTW/releases/tag/v1.0.2)**

Download the prebuilt driver from [Releases](https://github.com/JoMei9019-real/AirPort-RTW/releases).
The **Source code** downloads are for building the project, not installation.
For the changes in the stable version, see the [1.0.2 release notes](RELEASE_1_0_2.md).

Version 1.1.0 is being prepared with a focus on automatic roaming between
compatible access points. Development builds and their known limitations are
described on the [1.0.0-beta branch](https://github.com/JoMei9019-real/AirPort-RTW/tree/1.0.0-beta).
They are separate from the current stable release.

## Supported hardware


| Card | PCI vendor:device IDs | Status |
| --- | --- | --- |
| RTL8821CE | `10ec:c821`, `10ec:b821` | Supported |
| RTL8822BE | `10ec:b822` | Supported |
| RTL8822CE | `10ec:c822`, `10ec:c82f` | Supported |
| RTL8814AE | `10ec:8813` | Experimental; hardware validation pending |

RTL8812AE, USB and SDIO adapters are not
supported. A listed PCI ID does not guarantee that every laptop configuration
will work.

## Install or update

AirPort-RTW uses OpenCore. The required Apple Wi-Fi components depend on macOS:

| macOS | Setup |
| --- | --- |
| Ventura 13 | Use the system Wi-Fi components; add AirPortRTW |
| Sonoma 14, Sequoia 15, Tahoe 26 | Restore a compatible legacy Apple Wi-Fi stack, then add AirPortRTW |
| Monterey 12 and earlier | Not validated |

1. Back up your working EFI.
2. Follow the [installation guide for your macOS version](docs/INSTALLATION.md).
3. Place `AirPortRTW.kext` in `EFI/OC/Kexts/` and enable it in
   `config.plist → Kernel → Add`.
4. Disable older Feixiao `rtw88.kext` or duplicate AirPortRTW builds.
5. Reboot and connect from the macOS Wi-Fi menu.

For an ordinary update, replace the kext while keeping your working dependency
configuration. Check compatibility again when updating macOS.

## What to expect

The stable driver provides native network scanning and connection, 2.4/5 GHz
operation, WPA/WPA2 connection handling, and sleep/wake support. WPA2 is the
recommended starting point for testing.

Known limitations:

- Long/deep sleep, standby and hibernation are not guaranteed. Reconnection after
  wake may depend on the system configuration.
- AirDrop and the full set of Apple Continuity features are not supported by
  this stable release. Their development is separate.
- RTL8814AE remains experimental.
- The CoreWiFi `BSSID_CHANGED` length warning is not claimed fixed in 1.0.2.

## Troubleshooting and reporting a problem

Check that the driver attached after rebooting:

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

If there is no result, check the PCI ID, OpenCore entry, duplicate drivers and
the dependencies in the installation guide. If Wi-Fi connects, test Internet
access, Wi-Fi off/on and sleep/wake.

When opening an [issue](https://github.com/JoMei9019-real/AirPort-RTW/issues),
include the card/PCI ID, macOS version, `DriverBuild`, steps to reproduce and
relevant logs. Redact private information such as network names if needed.

## Development and credits

See [building from source](docs/BUILDING.md) for developer instructions.
AirPort-RTW derives from Feixiao's macOS rtw88 port and incorporates native
IO80211 work from the RTL88WiFi / AirPort_RTW88 lineage.
See [NOTICE.md](NOTICE.md) and the source license/copyright notices.
