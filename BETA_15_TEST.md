# AirPortRTW 2.0.0-beta.15

Beta 15 instruments the local AWDL TX handoff seen in Beta 14: tcpdump
sees local AirDrop mDNS while the controller's dequeue totals do not move.
This is a diagnostic build, not a confirmed AirDrop fix.

## Changes

- Separate IO80211 request callbacks from the existing timer-driven polls.
- Record the boolean dequeue return by service class, true with an empty
  list, false with a nonempty list, and reported versus actual packet counts.
- Observe Ethernet mDNS at three existing entry points: AWDL dequeue,
  controller outputPacket, and Ethernet BPF output. Observation never
  redirects a packet or changes its ownership, return value or retry behavior.
- Record the last dequeued packet length, EtherType and IPv6 next-header.
- Publish the new counters through the existing five-second diagnostic timer.
  The new hooks retain no payloads and add no per-packet registry writes.

The bool return is not treated as an IOReturn/error code. Controller and BPF
counters cover their respective general entry points, not just awdl0; their
mDNS counters can include infrastructure traffic. Controller retries may
count the same packet more than once. These are handoff observations, not
proof of RF transmission. The bounded mDNS observer uses the existing
Ethernet + IPv6 + direct UDP layout; it does not parse IPv6 extension headers.

AWDL RX filtering, A-MSDU handling, channel scheduling, peer timeout and
reconnect behavior are unchanged. Bundle version remains 2.0.0; diagnostic
build identity is 2.0.0-beta.15-awdl-tx-handoff.

## Hardware test

1. Replace AirPortRTW.kext in the existing OpenCore setup and reboot.
2. Confirm the build:

```sh
ioreg -l | grep -iE 'DriverBuild|AWDL_BETA_BUILD|AWDL_SCHEDULER_VERSION'
```

3. Close Finder AirDrop. Start this in a separate terminal:

```sh
sudo tcpdump -i awdl0 -e -n -vv -s0 'udp port 5353'
```

4. Take a baseline snapshot:

```sh
ioreg -l | grep -iE 'DriverBuild|AWDL_(TX_|IPV6_TX|MDNS_TX|AIRDROP_MDNS_TX|LOCAL_AIRDROP_SERVICE|RECEIVER_|DATA_TX|DATA_RX|VALID_PEERS|PEER_EXPIRES|ACTION_RX|RX_80211_DATA_SEEN|RX_NO_DS_SEEN|RX_REJECT_DS)'
```

5. Open Finder AirDrop with visibility Everyone. On the nearby iPhone,
   enable Wi-Fi/Bluetooth, choose Everyone for 10 Minutes and open a photo's
   Share > AirDrop sheet. Leave both open for 30 seconds.
6. Keep the windows open for another six seconds so the diagnostic snapshot
   can update, then repeat the same ioreg command and stop tcpdump with Ctrl+C.
7. Provide both snapshots, the capture, and whether either device appeared.

Compare SYSTEM_CALLBACKS/TIMER_POLLS, per-class BOOL returns, ACTUAL_DEQUEUED,
COUNT_MISMATCH and the three PATH/BPF_ETHERNET mDNS/AirDrop counters. Check that
DIAGNOSTIC_SAMPLES grows before interpreting an unchanged new counter.

## Validation

The new bounded packet observer was exercised on the host with address and
undefined-behavior sanitizers: null/short inputs, copy failure, all three
paths, IPv6/UDP/mDNS and service-ID recognition, scan truncation, and packet
immutability. Leak detection was disabled because the host disallows the
required process inspection. GitHub Actions performs the macOS x86_64 build,
plist lint, bundle/build identity checks and ZIP SHA-256 generation.
Hardware behavior must be established by the test above.
