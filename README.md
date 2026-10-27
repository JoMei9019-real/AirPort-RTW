# AirPort-RTW

A native macOS Wi-Fi driver for supported Realtek PCIe cards, integrated with
the normal macOS Wi-Fi menu. This branch prepares **1.1.0**, with a focus on
roaming between access points.

## Release status

**Development branch: `1.0.0-beta`. Version 1.1.0 is not published yet.**

The latest tested build on this branch is `1.1.0-beta.14-tx-flow-control`.
It remains a test build; the documentation cleanup does not change its driver
version or mark the unresolved issues as fixed.

- For regular use, download the [current stable release, 1.0.2](https://github.com/JoMei9019-real/AirPort-RTW/releases/tag/v1.0.2).
- For development builds, use the artifacts from a successful
  [Native AirPort build](https://github.com/JoMei9019-real/AirPort-RTW/actions/workflows/native-build.yml).
- See the [1.1.0 release notes draft](RELEASE_1_1_0.md) for the intended scope.

## What 1.1.0 adds

- **Automatic roaming:** choose another compatible access point on the same
  Wi-Fi network when the selection policy finds a better candidate.
- **Band preference:** prefer a sufficiently strong 5 GHz connection, with
  2.4 GHz available when appropriate. Eligible DFS targets require the normal
  passive discovery and regulatory checks.
- **802.11k roaming assistance:** Neighbor Reports and experimental Beacon
  Measurements help discover and describe nearby access points.
- **802.11v BSS Transition Management (BTM):** evaluate an AP's suggested
  switch with security, freshness, deadline and response-ACK checks.
- **Diagnostics:** the optional `rtw88-roam` tool reports roaming, wake timing,
  queue counters and measurement decisions.

802.11k/v support is limited to the implemented roaming-related functions.
Router capability labels are not proof of complete interoperability.
**802.11r Fast Transition is not implemented**, so a switch can briefly interrupt
traffic. BTM acceptance and Beacon Measurement interoperability still need
further hardware validation.

## Supported hardware

| Card | PCI vendor:device IDs | Status |
| --- | --- | --- |
| RTL8821CE | `10ec:c821`, `10ec:b821` | Supported |
| RTL8822BE | `10ec:b822` | Supported |
| RTL8822CE | `10ec:c822`, `10ec:c82f` | Supported |
| RTL8814AE | `10ec:8813` | Experimental; hardware validation pending |

RTL8814AE may be shown as RTL8813AE. RTL8812AE, USB and SDIO adapters are not
supported. This project targets x86_64 Hackintosh systems.

## Install or update

1. Back up your working EFI.
2. Follow the [OpenCore installation guide](docs/INSTALLATION.md). Ventura uses
   system Wi-Fi components; Sonoma, Sequoia and Tahoe require a compatible
   restored legacy stack.
3. Copy `AirPortRTW.kext` into `EFI/OC/Kexts/` and enable it under
   `Kernel → Add`. Disable older `rtw88.kext` and duplicate AirPortRTW builds.
4. Reboot, verify `DriverBuild`, and connect from the macOS Wi-Fi menu.
5. If using diagnostics, use the `rtw88-roam` executable from the same build.

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

## Known limitations

- **Packet loss under heavy traffic:** output-queue drops were reproduced
  during downloads/speedtests, including with AWDL hopping disabled. This is
  deferred from the roaming-focused 1.1.0 scope; investigation is planned for
  **1.1.1**. It is not fixed in this branch.
- **Wake reconnection can be slow.** One trace showed about a minute before
  connection startup. Deep sleep/hibernation reliability is not guaranteed.
- **WPA2-Enterprise is experimental and unverified on hardware.** WPA3, PMF,
  192-bit/SHA256 Enterprise and FT roaming are not advertised as supported.
- AirDrop/full Continuity support is not claimed by 1.1.0.
- Experimental RTL8814AE support still needs physical hardware validation.

## Testing, help and development

See [roaming and diagnostics](docs/ROAMING.md) for commands, live AWDL-hop
control, useful logs and the current validation status. Older beta-by-beta
notes have been removed from the current tree; they remain in Git history.

For an [issue](https://github.com/JoMei9019-real/AirPort-RTW/issues), include your
card/PCI ID, macOS version, `DriverBuild`, reproduction steps and redacted logs.
Developer build instructions are in [docs/BUILDING.md](docs/BUILDING.md).

AirPort-RTW derives from Feixiao's rtw88 macOS port and native IO80211 work from
the RTL88WiFi / AirPort_RTW88 lineage. See [NOTICE.md](NOTICE.md) and the
retained source license/copyright notices.
