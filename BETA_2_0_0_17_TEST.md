# AirPortRTW 2.0.0-beta.17

DriverBuild: **2.0.0-beta.17-awdl-tx-recursion-fix**.

Fixes Beta 16's double-fault panic in the native AWDL transmit callback.
The shipped Beta 16 binary's `drainAWDLTxPackets + 0x1c1` is the return
address of its new `isOutputFlowControlled()` virtual call (vtable offset
`0x8d0`). The reported Darwin 25 stack shows this call entering
`IO80211VirtualInterface::_outputStartGated`, then recursively calling
`requestPacketTx` and `drainAWDLTxPackets` until the kernel stack is exhausted.

The unsafe diagnostic call and its flow-control properties are removed.
An atomic scope guard also prevents recursive or concurrent native callbacks
from draining the same queue. Rejected nested calls leave queue ownership with
the original callback; the existing AWDL timer continues polling later.
`AWDL_TX_REENTRANT_SKIPPED` counts these rejected callbacks.

Beta 16's deferred RX, AWDL power fencing, and other TX diagnostics remain.
The 1.0.2 branch did not contain this diagnostic call and is not modified.
This fix does not establish working AirDrop transfers or reliable deep sleep.

## Hardware verification

1. Replace the old kext with this build and reboot. Verify `DriverBuild` with
   `ioreg -r -c AirPortRTW -l | grep DriverBuild`.
2. Open AirDrop on the Mac and a nearby iPhone repeatedly, and capture
   `sudo tcpdump -i awdl0 -e -n -vv -s0 'udp port 5353'`.
3. Check for another panic and record the `AWDL_TX_REENTRANT_SKIPPED`,
   `AWDL_TX_ACTUAL_DEQUEUED`, and `AWDL_AIRDROP_MDNS_TX_RESPONSES` counters.
4. Test sleep/wake separately, including extended standby. The earlier sleep
   timeout and this transmit stack overflow are separate failure paths.

Host regression checks cover the production drain guard's recursive callback,
packet ownership, competing callback, later callback, and early-return cases.
Native macOS CI builds the kext; the private IO80211 runtime ABI and hardware
sleep/transfer behavior still require testing on the affected machine.
