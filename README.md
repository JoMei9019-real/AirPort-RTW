# AirPort-RTW — 1.2.0 Beta 4

Development continues on the existing `1.0.0-beta` branch; the driver version
is `1.2.0-beta.4`. This beta tests WPA3-Personal through the normal macOS Wi-Fi
menu, using the existing IO80211 frontend. Read the
[Beta 4 instructions](RELEASE_1_2_0_BETA_4.md) before installation.
No connection helper is included in this package. A first hardware test
confirmed a WPA3/PMF menu connection; broader interoperability and Beta 4's
throughput improvements still require hardware testing.
Existing legacy Wi-Fi dependencies remain required; the frontend rebuild is
reserved for 2.0.0.

The stable-release instructions below describe **1.1.0**, not this beta.

A Wi-Fi driver for supported Realtek PCIe cards on x86_64 Hackintosh systems.
It works with the normal macOS Wi-Fi menu.

**Latest release: 1.1.0 — automatic roaming.**

[Download 1.1.0](https://github.com/JoMei9019-real/AirPort-RTW/releases/tag/v1.1.0)
· [Installation guide](docs/INSTALLATION.md)
· [Release notes](RELEASE_1_1_0.md)

## What it does

- Connect to Wi-Fi through macOS, without a separate connection app.
- Automatically switch between compatible access points on the same network.
  This is useful when moving around a home with several access points or repeaters.
- Prefer 5 GHz when its signal is strong enough, and use 2.4 GHz when needed.
- Use supported **802.11k and 802.11v** features to find nearby access points
  and consider switch suggestions from the router.

Roaming can briefly interrupt traffic. **802.11r Fast Transition is not
implemented.** Some 802.11k/v functions are experimental and still need testing
with more routers. A router showing “11k” or “11v” does not confirm every feature.

## Supported hardware

| Card | PCI vendor:device IDs | Status |
| --- | --- | --- |
| RTL8821CE | `10ec:c821`, `10ec:b821` | Supported |
| RTL8822BE | `10ec:b822` | Supported |
| RTL8822CE | `10ec:c822`, `10ec:c82f` | Supported |
| RTL8814AE | `10ec:8813` | Experimental; needs hardware testing |

RTL8812AE, USB and SDIO adapters are not supported. A listed card does not
guarantee compatibility with every laptop or EFI configuration.

## Install or update

1. Back up your working EFI folder and keep a way to restore it.
2. Download **AirPortRTW-1.1.0.zip** from the release page and extract it.
   The “Source code” downloads do not contain a ready-to-use driver.
3. Follow the [installation guide](docs/INSTALLATION.md) for your macOS version.
   Ventura uses the system Wi-Fi components. Sonoma, Sequoia and Tahoe need
   additional compatible legacy Wi-Fi components.
4. Put `AirPortRTW.kext` in `EFI/OC/Kexts/` and enable it in OpenCore under
   **Kernel → Add**. Disable older `rtw88.kext` or duplicate AirPortRTW copies.
5. Restart and connect from the macOS Wi-Fi menu.

If AirPortRTW already works on your current macOS version, replace its kext
and keep your working dependencies.

To check which build is loaded, run this in Terminal:

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

For this release, the result should show `1.1.0`.

## Turn off automatic roaming

Automatic roaming is enabled by default. To turn it off, add
**`-rtwnoautoroam`** to **NVRAM → Add → 7C436110-AB2A-4BBB-A880-FE41995C9F82 → boot-args**
in your OpenCore `config.plist`, keeping your existing arguments, then restart.
Remove this argument and restart to enable automatic roaming again.

## Known limitations

- **Heavy downloads or speed tests can cause packet drops.** This remains
  unresolved. Further investigation is planned for **1.1.1**.
- Reconnecting after sleep can be slow. Deep sleep and hibernation are not
  fully reliable on all systems.
- WPA2-Enterprise (work or school networks using 802.1X) is experimental and
  has not been verified on hardware. WPA3 and PMF are not supported.
- AirDrop and full Continuity support are not provided by this release.
- RTL8814AE support still needs testing on a physical card.

See [roaming and diagnostics](docs/ROAMING.md) for advanced settings, logs,
and details about what has been tested.

## Help and development

When [reporting a problem](https://github.com/JoMei9019-real/AirPort-RTW/issues),
include your Wi-Fi card, macOS version, loaded build, and steps to reproduce it.
Logs help; remove private information before sharing them.

Developers can use the [build guide](docs/BUILDING.md). Development continues
on `1.0.0-beta`; use a published release for normal installation.

AirPort-RTW builds on Feixiao's rtw88 macOS port and native IO80211 work from
the RTL88WiFi / AirPort_RTW88 projects. See [NOTICE.md](NOTICE.md) and the
license notices in the source files.
