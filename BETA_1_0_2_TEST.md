# AirPortRTW 1.0.2-beta.1

Based on main (6dc25ba), including the 1.0.1 NAPI stop fix. No 2.0.0-beta
changes are merged. Bundle and kmod versions are 1.0.2; the diagnostic identity
is 1.0.2-beta.1-deferred-rx.

## Change

NAPI previously ran RX protocol processing directly. That processing can
acquire the controller gate for link updates or the Realtek mutex for key
changes. Sleep can hold those locks while synchronously draining NAPI.

The native controller now receives owned skbs through a 256-packet queue.
A software interrupt event source processes at most 64 packets per workloop
turn. The producer only takes a short queue lock and signals the source;
it never enters the controller gate or processes RX protocol callbacks.
Overflow is counted and freed. The queue is closed and emptied before radio
power-off. Start/stop is serialized with the RX consumer using the parent
workloop gate. On teardown the consumer is removed before the backend is
released, and the event source remains alive until NAPI has been stopped.
NAPI enable state uses atomic loads/stores. The 1.0.1 synchronous drain is
retained: no forced power-off timeout or early freeing of live resources.

This addresses two code-level lock cycles consistent with the panic. The
panic contains only the waiting thread, so hardware testing must establish
whether this removes the observed failure. Queueing may affect latency or
packet loss under load; this is a beta, not a confirmed stable sleep fix.

## Checks

The host test extracts the production queue methods and checks FIFO and wrap,
overflow, bounded processing, packet ownership, concurrent close/reopen,
shutdown, and a producer completing while a simulated controller gate is
held. Run: python3 tests/check_deferred_rx.py. ASan/UBSan are enabled; host leak
inspection is disabled. This is not an IOKit scheduling or hardware test.
GitHub Actions builds the actual macOS x86_64 kext and checks its identity.

## Hardware test

1. Keep a bootable EFI backup. Replace only AirPortRTW.kext, then reboot.
2. Confirm the loaded build:

```sh
ioreg -l -w0 | grep -E 'DriverBuild|RX_DEFER_|PM_(STATE|SLEEP_COUNT|WAKE_COUNT|LAST_SLEEP_RESULT|LAST_WAKE_RESULT)'
```

DriverBuild must be 1.0.2-beta.1-deferred-rx. RX_DEFER_QUEUED and
RX_DEFER_PROCESSED should increase during Wi-Fi traffic. RX_DEFER_DROPPED
also includes packets discarded during power transitions.

3. Test normal browsing and download/upload, then several short sleep/wake
cycles, followed by the longer sleep that previously failed. Save the above
output before and after, and report the sleep duration and power source.
4. Record the current pmset configuration with pmset -g custom. If background
wake/standby have been disabled, a passing test covers only that setup; repeat
with your original settings later to validate the original trigger.
5. If another panic occurs, provide its complete report and loaded build.
