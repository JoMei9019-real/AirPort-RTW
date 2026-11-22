# AirPortRTW Beta 24 with AirBridge 0.1.0

Replace AirPortRTW.kext and add AirBridge.kext to EFI/OC/Kexts. In
Kernel/Add enable AirPortRTW first and AirBridge second. AirBridge uses
Contents/MacOS/AirBridge and Contents/Info.plist. Keep the existing Bluetooth
firmware and BroadTek setup. For the first boot leave
`-rtwairbridgenative`, `-rtwairbridgepeeradd` and the earlier experimental
`-rtwawdlapplerx` out of boot-args. Keep a bootable copy of the previous EFI.
Check Wi-Fi, sleep/wake and `AirBridgeMode = passive` first.

For a separate observer test add only `-rtwairbridgenative` and reboot.
Native peer creation requires a further explicit `-rtwairbridgepeeradd` test
after the observer has demonstrated stable processing.

AirBridge matches the AirPortRTW controller using its ABI property and handles
action frames synchronously on its workloop. Native access requires the loaded
IO80211FamilyLegacy UUID 4C07538B-62EB-3D6D-AEF9-93BCDCF45FAB. The bridge
checks the VIF owner, peer class and receive state. It can admit a locally
validated peer after a successful Apple parse and verifies the MAC in the native
table. An unsupported family or closed gate uses the existing Apple action tap.
This build uses the system's existing event delivery to wifip2pd.

Open AirDrop on both devices for 30 seconds. Compare the following snapshots
before and after, then try a small file in both directions.

```sh
kmutil showloaded | grep -E 'IO80211FamilyLegacy|jomei9019\.(AirBridge|AirPortRTW)'
ioreg -r -c RTWAirBridge -l | grep -E 'AirBridgeMode|AirBridgeFamilyVerified'
ioreg -r -c AirPortRTW -l | grep -E '"(DriverBuild|AWDL_BRIDGE_[^"]+|AWDL_RX_APPLE_ACTION_INPUTS|AWDL_DATA_RX|AWDL_AIRDROP_MDNS_RX)"'
```

FamilyVerified confirms the UUID. OBSERVED counts native parser calls,
PROCESSED counts actions that changed its receive statistics, and PEER_MATCHES
counts source-address matches following a lookup. File transfer is the
end-to-end test. To revert, restore the previous AirPortRTW and disable the
AirBridge entry in Kernel/Add.
