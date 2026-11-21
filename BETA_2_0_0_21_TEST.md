# AirPortRTW 2.0.0 Beta 21

This build brings the QoS HT Control receive fix from 1.3.1 into the 2.0.0
branch. For AWDL, the parser uses the full 802.11 header length before
looking for the direct or length-prefixed SNAP envelope. The station path
uses the QoS Control offset for the TID and A-MSDU flag. WPA3 verification
uses the corrected offset for CCMP.

In the RTL8821CE test with BroadTek 4acb828, macOS started BLE advertising
and the driver received AWDL action frames. AirDrop discovered no peers and
the AWDL data RX counter stayed at zero. The existing test could not tell
whether any of the incoming frames carried HT Control.

## Hardware check

Keep the Beta 20 boot arguments and the working BroadTek build. Open AirDrop
on both devices, select Everyone, and capture these counters before and after
a 30-second discovery window.

```sh
ioreg -r -c AirPortRTW -l |
  grep -E '"(DriverBuild|AWDL_(VALID_PEERS|DATA_(RX|TX)|RX_(NO_DS_SEEN|BSSID_MATCH|QOS_HT_CONTROL_FRAMES|WRAPPED_SNAP|REJECT_SNAP|REJECT_DESTINATION|ETHERNET_DELIVERED)|AIRDROP_MDNS_(RX|TX)(_RESPONSES)?))"'
```

An increased `AWDL_RX_QOS_HT_CONTROL_FRAMES` shows the corrected header
path was used. If `AWDL_RX_BSSID_MATCH` stays at zero, the driver has not
seen a matching AWDL data frame in that window. If discovery works, try
one small transfer in each direction.
