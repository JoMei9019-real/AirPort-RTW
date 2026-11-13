# AirPortRTW 1.3.0 Beta 5

- Corrects the private-address wire layout and handles selector 238 at the native controller request. IO80211FamilyLegacy checks the BSD buffer and copies its payload. AirPortRTW then handles the kernel buffer for the primary Wi-Fi interface.
- Answers the permanent hardware address request (selector 359) from the card's factory address. When macOS supplies a station address, the driver updates the radio and BSD interface together while the station is idle. macOS owns per-network policy and rotation.
- Starts Bluetooth maintenance after the radio and station are initialized and drains the worker before PCI teardown. RF watchdog behavior is unchanged. Bluetooth throughput on 2.4 GHz still needs a hardware test.

## Reference and limits

The [Ventura Legacy reference bundle](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/e21efa975c0cf228cb36e81a974bc6b4c27c7807/payloads/Kexts/Wifi/IO80211FamilyLegacy-v1.0.0.zip) contains IO80211FamilyLegacy 1200.12.2b1 and AirPortBrcmNIC 1400.1.1. The family marshals 28 bytes for selector 238. The Broadcom driver reads enable, flags, timeout and MAC address at byte offsets 4, 8, 12 and 16. The ZIP from [issue #6](https://github.com/JoMei9019-real/AirPort-RTW/issues/6) places the timeout and MAC address at different offsets.

The Settings control still needs verification on the target macOS version. The build does not add capability bits. It records whether the host invokes the native private-address request, the hardware-address query, the Ethernet address setter or the separate selector 368. Selector 368 remains unsupported pending confirmation of its payload.

## Hardware check

1. Confirm that System Information reports `AirPortRTW 1.3.0-beta.5`. In **System Settings → Wi-Fi → Details**, open **Private Wi-Fi Address** for a test network.
2. If the menu is available, choose **Off**, reconnect and compare the client's address at the access point with the factory address. Choose **Fixed** and confirm that the access point sees a different address that stays the same across a reconnect and sleep/wake.
3. Choose **Rotating**, confirm that the connection works, and check that the address changes when macOS rotates it. A quick reconnect alone does not verify rotation. Repeat a WPA2/WPA3 join and a roam on the same SSID.
4. If the menu stays disabled, or a reconnect fails, report the macOS build, Legacy kext version and this filtered output. It contains selector status and lengths, without addresses.

```sh
sw_vers
kmutil showloaded 2>/dev/null | grep -E 'IO80211FamilyLegacy|IOSkywalkFamily'
ioreg -l -w0 | grep -E '"(DriverBuild|STA_PRIVATE_MAC_[A-Z_]+|STA_MAC_[A-Z_]+)"'
```
