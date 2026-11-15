# AirPortRTW 1.3.0 Beta 7

Beta 7 reads the private station address that Intel macOS Tahoe can include directly in its 908-byte association request. On macOS 26.7.3 (25G342), `Apple80211Associate2` marks the address with bit `0x08` at offset `0x1d4` and stores the six bytes at `0x200`. macOS selects the network address and its rotation policy.

The driver applies the address to the Realtek station and BSD interface before the authentication worker starts. This also covers joins that wait for a scan to finish. An ordinary join can restore the permanent address after an address applied by this path. Driver-managed roaming between access points keeps the current address.

## Hardware check

Reconnect to the test network and verify traffic. Check the client's active address at the router against the saved private address on the Mac. Also check whether the **Private Wi-Fi Address** selector can be changed in System Settings. The state of the selector needs a hardware check independently of address use during association.

```sh
ioreg -r -c AirPortRTW -l -w0 | grep -E '"(DriverBuild|STA_ASSOC_BSD_LEN|STA_ASSOC_PRIVATE_MAC_[A-Z_]+)"'
```

- `STA_ASSOC_PRIVATE_MAC_REQUEST = "private"` means Tahoe supplied a locally administered unicast address.
- `"absent"` means the decoded Tahoe request carried no private address. `"invalid"` means the marked address failed validation and the join was rejected.
- `STA_ASSOC_PRIVATE_MAC_APPLY_RET = 0` with `STA_ASSOC_PRIVATE_MAC_ACTIVE = Yes` records a successful private address application before authentication. The router can confirm the resulting association.
