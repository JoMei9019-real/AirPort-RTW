# AirPort-RTW 1.2.0

This release adds **WPA3-Personal** to the normal macOS Wi-Fi menu. You can
connect without installing a separate connection app. It also improves
network switching and fixes a problem that could stop roaming scans.

## What's new

- **WPA3-Personal connections.** SAE authentication and Protected Management
  Frames (PMF) are supported, including on WPA2/WPA3 transition networks.
- **Faster WPA3 traffic.** Pairwise CCMP encryption uses the card's hardware
  by default. This improved speed and CPU use compared with the earlier
  software-only WPA3 builds.
- **WPA3 roaming.** The driver can switch between compatible access points
  on the same network while keeping WPA3. Both automatic and manually
  requested switches were observed in device testing.
- **More reliable network changes.** Disconnects, Wi-Fi toggling and the
  connection state shown to macOS have been improved. macOS is also told
  when an access point has rejected a connection attempt.
- **Scan stability fixes.** WPA3 key updates no longer overwrite a running
  scan's state and timer, which could leave further scans and roaming blocked.
- **Safer diagnostic requests.** The release includes fixes for the error
  query and kernel-stack problems reported while using Wi-Fi diagnostics.

Automatic roaming and the supported 802.11k/v functions remain available.
**802.11r Fast Transition is not implemented**, so an AP switch still needs
a new authentication exchange and can briefly interrupt traffic.

## Known issues

- **Some starts may connect using WPA2 first.** This was reported on a
  WPA2/WPA3 transition network; manually disconnecting and reconnecting selected
  WPA3. Other starts connected directly with WPA3. The cause is still being
  investigated, so WPA3 is not guaranteed on every automatic connection.
- **Some WPA3 attempts may be rejected before a later attempt succeeds.**
  The access point returned SAE status 15 in the recorded cases. This does
  not by itself establish a wrong password or the cause of the rejection.
- **One WPA3 guest network did not provide an IP address.** Authentication
  succeeded, but the capture showed unanswered DHCP requests. The cause may
  involve the network or the driver and has not been established.
- Heavy downloads and speed tests can still cause packet drops. This release
  does not claim to resolve all traffic-related losses.
- Reconnecting after sleep may be slow. Deep sleep and hibernation remain
  dependent on the system and are not fully validated.
- WPA2-Enterprise and RTL8814AE support remain experimental. WPA3-Enterprise,
  pure pairwise TKIP, AirDrop and full Continuity support are not included.

Device testing covered WPA3 startup, hardware CCMP, network changes and roaming.
The 29 driver regression checks, crypto tests, native macOS build and compiled
IOCTL stack checks are run for the release. This does not establish
compatibility with every card, router or macOS configuration.

## Download and update

Download **AirPortRTW-1.2.0.zip** and extract it once. It contains only:

- `AirPortRTW.kext`
- `BOOT-ARGS.txt`, listing the four supported driver boot arguments

License notices are kept inside the kext bundle. Connection tools, test
captures and beta documents are not included in the ZIP. A separate SHA-256
file is available for checking the download.

Back up your EFI, replace `AirPortRTW.kext`, and restart. Keep the compatible
Apple Wi-Fi dependencies used by your working installation. New installations
should follow [the installation guide](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.2.0/docs/INSTALLATION.md).
Sonoma and newer still require the compatible legacy Wi-Fi stack.

Check the loaded version in Terminal:

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

It should show **`1.2.0`**.

Automatic roaming is enabled by default. Add **`-rtwnoautoroam`** to your
existing OpenCore `boot-args` and restart to turn it off. Remove the argument
and restart to turn it on again. The other diagnostic options are explained
in [BOOT-ARGS.txt](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.2.0/docs/BOOT-ARGS.txt).

Thanks to the original authors and everyone testing the driver. Credits and
licenses are listed in [NOTICE.md](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.2.0/NOTICE.md).
