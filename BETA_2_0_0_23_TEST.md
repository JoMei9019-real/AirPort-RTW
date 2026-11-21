# AirPortRTW 2.0.0 Beta 23

Beta 23 publishes the AirBridge ABI on the controller and its AWDL virtual
interface. The existing Apple action frame path runs through a dedicated entry
point when `-rtwawdlapplerx` is enabled. AirPortRTW works on its own and
continues to own the RTL8821CE receive filter, timing and single-radio channel
selection.

## Test on the RTL8821CE

Keep BroadTek `4acb828` and the Beta 22 boot arguments for a comparable test.
Open AirDrop on the Mac and the iPhone for 30 seconds. Take snapshots before
and after discovery.

```sh
ioreg -r -c AirPortRTW -l |
  grep -E '"(DriverBuild|AirPortRTWAirBridgeABI|AWDL_(BRIDGE_[^"]+|VALID_PEERS|RX_(APPLE_ACTION_INPUTS|HW_[^"]+|BSSID_MATCH)|DATA_RX|TX_DATA_COMPLETED|AIRDROP_MDNS_RX))"'
```

- `AirPortRTWAirBridgeABI = 1` identifies the prepared frontend.
- `AWDL_RX_HW_FILTER_VALID` identifies a usable sample of the live Realtek
  receive configuration register. `AWDL_RX_HW_FILTER_PERMISSIVE` means the
  register accepts all destination addresses and multicast with the beacon
  and data BSSID filters clear. Use it together with `AWDL_RX_BSSID_MATCH`
  to distinguish a restored hardware filter from a lack of matching data RX.
- `AWDL_RX_APPLE_ACTION_INPUTS` counts submissions via the existing Apple
  action tap. `AWDL_VALID_PEERS` is the AirPortRTW peer count.
- `AWDL_BRIDGE_ACTIONS_OBSERVED`, `AWDL_BRIDGE_ACTIONS_PROCESSED`,
  `AWDL_BRIDGE_PEER_LOOKUPS` and `AWDL_BRIDGE_PEER_MATCHES` stay at zero
  until the companion reports native evidence. Peer matches count verified
  lookups per action frame. A single peer can match several times.

## AirBridge integration

1. Use [AirPortRTWAirBridge.hpp](src/kext/AirPortRTWAirBridge.hpp) as the
   shared ABI. Resolve `_rtw88_airbridge_action_v1` in the
   `io.github.jomei9019.AirPortRTW` image. The Beta 23 build summary records
   its x86_64 Mach-O UUID. Validate the loaded frontend and the actual
   `IO80211FamilyLegacy` UUID and native symbols before installing routes.
2. Require ABI 1 and the exact request size. Scope AWDL hooks to the
   AirPortRTW-owned `IO80211P2PInterface` carrying ABI 1 and confirm the
   interface's controller and active AWDL binding. Keep client authorization
   and lifecycle checks in the companion. Forward calls outside that scope
   through the original entry.
3. On a supported Apple family build, sample the bound peer manager, call the
   original synchronously once, then verify the parser's action RX counter
   and look up the action's source address under the native lock. Set result
   flags only for observed, verified outcomes. The caller owns the mbuf and
   stack metadata. The companion must finish reading them before returning.
   `handoffUS` is host monotonic time at handoff, and
   `kLocalPeerValid` describes the driver's local parser result.
4. Validate the native actions and peer lookup first. Exercise any later
   event or client adapter with discovery and a file transfer in both
   directions, then repeat after sleep and wake.

The reference is [RTLAirLink at b75abf4](https://github.com/xnpty/RTLAirLink/tree/b75abf4ccc4fccb8a423adc0d41b37643d9991e5).
The reference's frontend UUID, readiness properties and rtw89 hardware CAM
programming are specific to RTLAirLink. Beta 23 uses the existing rtw88 filter
with register readback. The companion kext is a separate build.
