# AirPortRTW 2.0.0 Beta 22

Beta 21 saw no AWDL data frames with the expected BSSID on the test RTL8821CE.
Beta 22 keeps the peer's advertised next channel as a fallback for an empty
slot when it matches the AP channel. The fallback now applies on both sides
of the scheduler's channel check. If a slot has no usable channel, the
scheduler restores the AP channel after an off-channel window.

The AWDL data TX counter now records packets accepted by the Realtek PCI ring.
TX failures include ring rejections. The completion counter records PCI
descriptor reclamation. In particular, multicast completion does not tell
whether the iPhone received a frame.

## Hardware check

Keep the Beta 21 boot arguments and BroadTek 4acb828. Open AirDrop on both
devices and compare the counters before and after 30 seconds of discovery.

```sh
ioreg -r -c AirPortRTW -l |
  grep -E '"(DriverBuild|AWDL_(DATA_(RX|TX)|TX_(ATTEMPTS|FAILURES|DATA_COMPLETED)|PEER_NEXT_AW_FALLBACK_WINDOWS|RX_(NO_DS_SEEN|BSSID_MATCH|ETHERNET_DELIVERED)|AIRDROP_MDNS_(RX|TX)(_RESPONSES)?))"'
```

If discovery still fails while joined to a Wi-Fi network, disconnect from the
network with Wi-Fi and Bluetooth left on. Repeat with AWDL free to use the
radio without an associated AP.
