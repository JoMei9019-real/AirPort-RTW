# AirPortRTW 1.3.0 Beta 4 — test build

Beta 4 is an **experimental test artifact**, not a release or pre-release.

## Changes

- Added Apple80211 selector 238 handling for private Wi-Fi addresses through BSD IOCTL, Legacy split GET/SET and Skywalk split GET/SET, based on the community patch from issue #6.
- Routes the CoreWiFi-requested station MAC through the existing `setMACAddress` logic before association. Private address Off restores the immutable hardware address.
- Stores macOS-supplied enable/flags/timeout metadata; rotation remains CoreWiFi's responsibility (no independent rotation timer).
- Added private-MAC ingress counters and last result properties without logging private MAC addresses.
- Restored periodic Realtek Bluetooth coexistence firmware status queries in a dedicated maintenance worker. The original RF-dynamic Linux watchdog stays disabled.
- Skips coexistence polling while scanning, in low-power states, or when the device is not running, and cancels the worker during shutdown.
- Kept Beta 3 open-network and dynamic rate/MCS/NSS support.

## Important limits

The 28-byte selector-238 field mapping comes from the community patch and is inferred rather than publicly documented. Fixed, Rotating and Off must be tested on the actual macOS/IO80211FamilyLegacy combination; successful compilation is **not** proof of runtime compatibility.

Bluetooth coexistence improvements are also not confirmed until hardware tests. Some slowdown on 2.4 GHz is expected, but the Beta 3 drop from ~30 to 2–3 Mbit/s warrants investigation.

## Suggested hardware validation

1. On a known WPA2/WPA3 network, open Wi-Fi Details and verify **Private Wi-Fi Address: Off**; reconnect and check that the original hardware address is used.
2. Disconnect, change to **Fixed**, reconnect and verify that the network uses a stable randomized address. Do not publicly post the full MAC.
3. Verify **Rotating** is selectable and joining works; actual rotation requires a longer CoreWiFi-controlled test.
4. Repeat the 2.4 GHz Speedtest with Bluetooth Off, On/unconnected, discovering nearby devices, and connected audio. Observe TX rate and MCS during scan and after closing Bluetooth Settings.
5. Confirm 5 GHz throughput and audio, and test WPA3 rejoin, scan, sleep/wake.

Useful IORegistry diagnostics: `STA_PRIVATE_MAC_GET_SEEN`, `STA_PRIVATE_MAC_SET_SEEN`, `STA_PRIVATE_MAC_LAST_RET`, and `STA_PRIVATE_MAC_SET_COUNT`. Do not share full private MAC addresses.

If a hardware test shows link loss, kernel panic or Bluetooth interruption, revert to the last known-good Beta 3 build.
