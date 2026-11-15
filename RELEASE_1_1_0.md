# AirPort-RTW 1.1.0

This release focuses on **roaming**: switching between access points on the
same Wi-Fi network as you move around. It includes the changes tested through
1.1.0 Beta 14.

## What's new since 1.0.2

- **Automatic AP switching.** The driver checks nearby access points and can
  move to a better compatible connection without a manual command.
- **5 GHz preference with 2.4 GHz fallback.** A strong 5 GHz connection is
  preferred. Signal checks and a cooldown help avoid unnecessary switches.
- **DFS channel support for roaming.** Suitable access points on these 5 GHz
  channels can be used after discovery and the required channel checks.
- **802.11k assistance.** The driver can request a list of nearby access
  points and respond to supported Beacon Measurement requests. Measurement
  support remains experimental.
- **802.11v assistance.** The driver can consider a router's suggested AP
  change and accept or decline it after checking the target and connection.
- **More diagnostics.** Additional connection, roaming and wake information
  helps with investigating problems.
- **Experimental WPA2-Enterprise support.** An initial connection path for
  work/school networks is included, but has not been verified on hardware.

Automatic AP switches and working Internet after 2.4/5 GHz changes have been
observed in testing. A switch may briefly interrupt traffic: **802.11r Fast
Transition is not implemented**. Router-initiated accepted 802.11v switches
and 802.11k measurement replies still need more real-world testing. This is
not a claim of complete support for every optional 802.11k/v feature.

## Known issues

- Heavy downloads and speed tests can cause packet drops, even without an
  AP switch or AWDL channel hopping. This is not fixed in 1.1.0; investigation
  is planned for **1.1.1**.
- Reconnecting after sleep can take longer than expected. One test took
  about a minute before connection startup. Deep sleep and hibernation remain
  dependent on the system and are not fully validated.
- WPA3, PMF and 802.11r are not supported. WPA2-Enterprise is experimental;
  advanced Enterprise security modes and fast-roaming key caching are not
  advertised as supported.
- AirDrop and full Continuity support are not included.
- RTL8814AE remains experimental and needs physical hardware testing.
  RTL8812AE, USB and SDIO adapters are not supported.

## Download and update

Download **AirPortRTW-1.1.0.zip** from this release and extract it once.
It contains `AirPortRTW.kext` and guides. The developer CTL tool is not included.
Do not use GitHub's “Source code” downloads to install the driver.

Back up your EFI, replace `AirPortRTW.kext`, and restart. Keep the compatible
Wi-Fi dependencies already used by your working setup. New installations
should follow [the installation guide](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.1.0/docs/INSTALLATION.md).

Check the loaded version in Terminal:

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

It should show `1.1.0`.

## Turn off automatic roaming

Automatic roaming is enabled by default. To disable it, add **`-rtwnoautoroam`**
to the existing `boot-args` in your OpenCore `config.plist`, then restart.
Remove the argument and restart to enable automatic roaming again.
More commands are in [the roaming guide](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.1.0/docs/ROAMING.md).

Thanks to the original driver authors and everyone testing and reporting
problems. See [NOTICE.md](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.1.0/NOTICE.md) for credits.
