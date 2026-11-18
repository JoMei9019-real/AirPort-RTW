# AirPortRTW 2.0.0 Beta 19

The experimental Apple AWDL receive path uses the channel from the RX frequency
when available and includes 20 MHz and DFS metadata. The driver still filters
Service Response and ARPA TLVs on this path to avoid the legacy IO80211
decompressor.

AWDL also accepts length-prefixed, non-aggregated QoS data frames observed
with iOS 27. The RX path checks the declared length and inner AWDL envelope
before delivering the payload.

## AirDrop hardware test

1. Install the Beta 19 kext, add `-rtwawdlapplerx` to the existing boot
   arguments, and reboot. Leave AWDL hopping enabled for the test. If
   `-rtwnoawdlhop` is set, use the existing `rtw88-roam --awdl-hops on`
   command after boot.
2. Open AirDrop on both devices, select Everyone, and run these commands
   before and after a 30-second discovery window.

   ```sh
   ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|AWDL_(RX_APPLE_ACTION|SYNC_GET|SERVICE_RESPONSE_RX|RX_WRAPPED_SNAP|AIRDROP_MDNS_RX)'
   ndp -an | grep awdl0
   ```

3. Check whether the Mac sees the iPhone and whether the iPhone sees the Mac.
   If a device appears, try sending a photo and record the direction.
   Collect the daemon's log for the same window.

   ```sh
   sudo log show --last 2m --info --style compact --predicate 'process == "wifip2pd"' |
     grep -Ei 'peer presence|awdl0|browse|sync'
   ```

`AWDL_RX_APPLE_ACTION_INPUTS` counts calls to Apple's entry point.
`AWDL_SYNC_GET_PRIMARY_ENABLED` and `AWDL_SYNC_GET_VIF_ENABLED` record
the last successful sync-mode query on each interface. A rising wrapped-SNAP
count is expected only when the peer actually sends that format.

Reference for the channel flags and the iPhone data-frame format
[RTL8814Native iPhone test notes](https://github.com/DrogaBox/RTL8814Native/blob/095b9c931ce45b7d80317426f207885f5b3ddac7/Docs/en/AWDL_RESULTADO_IPHONE_1.md).
