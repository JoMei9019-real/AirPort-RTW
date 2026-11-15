# AirPortRTW 2.0.0 Beta 18

This build combines the 1.3.0 Beta 8 driver with the 2.0.0 Beta 17 AWDL
implementation. It retains the deferred RX and TX recursion fixes. The
AWDL radio path keeps the 1.3.0 roaming/scan arbitration and Bluetooth
coexistence worker. The Wi-Fi Kext preserves the radio's Bluetooth
coexistence setting. The runtime log includes periodic coexistence worker
activity on supported hardware.

1. Boot the test EFI with the Beta 18 Wi-Fi Kext and your working Bluetooth
   setup. Verify Wi-Fi, Bluetooth, and the build before opening AirDrop.
2. Enable AirDrop receiving for everyone on both devices. Open AirDrop and
   try a small file in each direction. Capture the counters below with the
   window open. Then repeat with Bluetooth audio active, and test sleep/wake.
3. For an A/B test, add only `-rtwawdlapplerx` and reboot. The alternate
   RX path sends the AWDL action body, measured RSSI and channel to the
   native Apple peer manager. Its input result records the call, so also
   check Finder visibility and remote mDNS. Keep the same AP and iPhone
   settings across both boots.

```sh
ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|AWDL_(RX_APPLE_ACTION|VALID_PEERS|RX_BSSID_MATCH|RX_NO_DS_SEEN|DATA_RX|AIRDROP_MDNS|TX_ACTUAL_DEQUEUED|TX_DEQUEUE_WRAPPED|HOPS)'
ifconfig awdl0
sudo tcpdump -i awdl0 -n -e 'udp port 5353'
```

Reference: FranciumOS-org/AirPort_RTW89 commits
[1ecbb96](https://github.com/FranciumOS-org/AirPort_RTW89/commit/1ecbb969cdd0a908363fdfec478bd10586d8ce4e)
(action RX), [f98563e](https://github.com/FranciumOS-org/AirPort_RTW89/commit/f98563e992b4b0dbf34993836694a9279f2c6ec4)
(TX envelope), and [b011be2](https://github.com/FranciumOS-org/AirPort_RTW89/commit/b011be2e53b7b928fbcdf1b4b0bc6af5f202a82e)
(mDNS destination).
