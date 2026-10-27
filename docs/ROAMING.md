# Roaming in AirPort-RTW 1.1.0

Roaming means switching between access points on the same Wi-Fi network.
For example, your laptop can move from one repeater to another as you walk
through your home. No extra app is needed.

## How it works

Automatic roaming is enabled by default. The driver checks nearby access
points and can switch when it finds a better compatible connection.

- A strong 5 GHz connection is preferred.
- 2.4 GHz can be used when 5 GHz is too weak or unavailable.
- The target must use the same network name and compatible security.
- Allowed DFS channels can be used after the required discovery and channel checks.
- Signal thresholds and a 60-second cooldown help avoid repeated switches
  back and forth.

A switch can briefly interrupt traffic. **802.11r Fast Transition is not
implemented**, so the driver still needs to authenticate and set up encryption
with the new access point.

## Turn automatic roaming off or on

To turn it off, add **`-rtwnoautoroam`** to your existing OpenCore boot arguments:

1. Open your EFI's `OC/config.plist` in your usual configuration editor.
2. Go to **NVRAM → Add → 7C436110-AB2A-4BBB-A880-FE41995C9F82 → boot-args**.
3. Add `-rtwnoautoroam`, separated from other arguments by a space.
   Keep your existing arguments.
4. Save and restart macOS.

Remove this argument and restart to enable automatic roaming again.
Disabling automatic roaming does not disable Wi-Fi.

## Check the loaded driver

Open Terminal and run:

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
```

For this release, the result should show `1.1.0`.

## Try roaming

1. Connect to a Wi-Fi network with at least two compatible access points.
2. Start near one access point and check that websites load.
3. Move closer to the other access point and stay there for a few minutes.
   Switching is not immediate or guaranteed whenever another AP is nearby.
4. Check your router's client list, if available, to see which access point
   the laptop is using. Then check Internet access again.

A stronger signal alone does not confirm a switch. The router's connection
information can help confirm the access point, while loading a website checks
that Internet access still works.

If reporting a problem, note the time, your location, whether a download was
running, and whether Internet access recovered. Include your card, macOS
version and loaded driver build. Remove private information from any logs
or screenshots before sharing them.

## What 802.11k and 802.11v add

**802.11k** lets the driver request a list of nearby access points. Supported
Beacon Measurements can also describe nearby APs; this part is experimental.

**802.11v** lets a router suggest a different access point. The driver checks
the suggestion and can accept or decline it. It does not blindly follow
the router's recommendation.

These are the implemented roaming-related functions, not every optional
feature of either standard. A router showing “11k” or “11v” confirms advertised
capabilities, not complete compatibility. Router-initiated accepted switches
and Beacon Measurement replies still need testing with more hardware.

## Known limitations

- Heavy downloads and speed tests can cause packet drops, even without an
  AP switch. This is unresolved; investigation is planned for **1.1.1**.
- Reconnecting after sleep can be slow. Deep sleep and hibernation are not
  fully validated on all systems.
- WPA2-Enterprise is experimental and has not been verified on hardware.
  WPA3, PMF and 802.11r are not supported.

See the [release notes](../RELEASE_1_1_0.md) for the full release scope and
the [installation guide](INSTALLATION.md) for setup.
