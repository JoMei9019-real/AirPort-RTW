# AirPortRTW 2.0.0-beta.16

Base: beta-2.0.0 Beta 15. Bundle and kmod version remain **2.0.0**.
DriverBuild: **2.0.0-beta.16-awdl-pm-diagnostics**.

## Changes

- Includes the bounded deferred RX queue and atomic NAPI enabled flag from
  1.0.2-beta.1. NAPI transfers RX ownership without taking the controller gate;
  IO80211, AWDL peer parsing and protocol processing run on its workloop.
- AWDL now has a persistent power suspension fence. Cancel its timer and flush
  queued action/data packets before radio stop; late discovery, timer, enqueue
  and TX callbacks cannot reopen it. Ordinary Wi-Fi OFF also enters this fence.
- Resume AWDL only from explicit successful radio/VIF enable. System wake keeps
  the existing policy that defers AWDL during firmware restore/CoreWiFi reconnect.
- Suppress output-queue wakeups while AWDL/radio power is being stopped.
- Observe virtual-interface enable/disable results, outputStart calls, TX callback
  flow-control state, opaque output parameter matches, mDNS query/response counts
  and whether controller-path mDNS has the local AWDL source MAC.
- Peer notification diagnostics now include source MAC, channel, subtype and
  hexadecimal raw return values. These remain private ABI telemetry, not proof
  that macOS accepted a peer. Flow state is sampled during existing dequeue
  callbacks, not a continuous queue-state measurement. Pointer matches are
  observations, not a contract for the meaning of outputPacket's param.

No forced shutdown timeout, skipped NAPI synchronization, automatic queue start,
flow-control clearing or speculative mDNS rerouting is introduced.

## AirDrop test

With AirDrop open on the computer, keep iPhone AirDrop closed initially:

```sh
ioreg -l -w0 | grep -E '"(DriverBuild|AWDL_[A-Z0-9_]+|RX_DEFER_[A-Z0-9_]+|PM_[A-Z0-9_]+)"' > ~/Desktop/awdl-vorher.txt
sudo tcpdump -i awdl0 -e -n -vv -s0 'udp port 5353'
```

Open iPhone AirDrop, select Everyone for 10 Minutes, keep it unlocked nearby for
30 seconds, then Ctrl+C. Wait five seconds for diagnostic publication:

```sh
ioreg -l -w0 | grep -E '"(DriverBuild|AWDL_[A-Z0-9_]+|RX_DEFER_[A-Z0-9_]+|PM_[A-Z0-9_]+)"' > ~/Desktop/awdl-nachher.txt
diff -u ~/Desktop/awdl-vorher.txt ~/Desktop/awdl-nachher.txt
```

Also record `ifconfig awdl0` and whether either device becomes visible.

## Power test

1. Confirm normal Wi-Fi and AirDrop discovery diagnostics first.
2. Turn Wi-Fi OFF, wait five seconds, then inspect `AWDL_POWER_SUSPENDED`.
   It should be Yes. Turn Wi-Fi ON and confirm normal connectivity again.
3. Test a short sleep/wake, then a longer sleep. Record the IORegistry properties
   above before and after, and provide the full panic report if one occurs.
4. Record `pmset -g custom`; previously changed standby/Power Nap settings affect
   which sleep states are actually exercised. Do not change them for this test.

The host sanitizer tests exercise the production deferred-RX and AWDL power/queue
methods with mocks, including ownership and late discovery/suspend races. They
cannot validate IOKit private ABI behavior, RF delivery or sleep on actual hardware.
A successful native build is not proof that the reported panic is eliminated.
