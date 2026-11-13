# AirPortRTW 1.3.0 Beta 6

Beta 6 handles `SET_MAC_ADDRESS` (Apple80211 selector 368) for the primary Wi-Fi interface. The request carries six raw address bytes. AirPortRTW validates the BSD request length, lets IO80211FamilyLegacy copy the payload, and applies the address through the existing station MAC change path. This updates the hardware and the BSD address together. Address changes are rejected during an active link, handshake or scan. macOS continues to select the address and manage rotation.

## Reference

The x86_64 kernel debug kit for macOS 26.7.3 (25G342) confirms that `setSET_MAC_ADDRESS` requires six bytes and that the Skywalk interface passes the first byte of that payload to its MAC address agent. The loaded Ventura-era IO80211FamilyLegacy 1200.12.2b1 uses a zeroed 12-byte buffer for selector 368 before calling the controller. The first six bytes hold the same address.

## Hardware check

1. Boot with Beta 6, reconnect to the test network and verify that traffic works.
2. Compare the current client address at the router with the private address macOS saved for that network.
3. Check whether **System Settings → Wi-Fi → Details → Private Wi-Fi Address** can be changed. The condition that enables this menu on Tahoe with IO80211FamilyLegacy remains unconfirmed.
4. Record whether selector 368 reached AirPortRTW and what it returned. The filter below prints only the build and request status.

```sh
ioreg -r -c AirPortRTW -l -w0 | grep -E '"(DriverBuild|STA_PRIVATE_MAC_[A-Z_]+|STA_MAC_[A-Z_]+)"'
```
