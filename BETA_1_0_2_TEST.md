# AirPortRTW 1.0.2-beta.2

Based on 1.0.2-beta.1 on branch 1.0.0-beta, descended from main (6dc25ba).
This selectively ports the AWDL power fencing from 2.0.0-beta.16; AirDrop
features and extensive TX diagnostics from that branch are not merged.
Bundle and kmod versions remain 1.0.2; DriverBuild is
1.0.2-beta.2-awdl-power-fence.

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

## Beta 2 additions

AWDL is persistently suspended before either system sleep or ordinary radio
power-off: cancel its timer, return the PHY to the infrastructure channel and
flush owned action/data packets. Late discovery, enqueue, RX/TX callbacks and
output-queue wakeups cannot reopen the power fence. Resume only after explicit
successful radio/VIF enable; retain deferred AWDL during system firmware wake.
If a Wi-Fi OFF request fails because a scan is still busy, reopen RX for the
still-powered device. No hard-coded forced shutdown or skipped NAPI drain.

Power diagnostics: AWDL_POWER_SUSPENDED, AWDL_POWER_SUSPENDS and
AWDL_POWER_RESUMES. A peer or RX count is not proof of successful AirDrop.

## Checks

The host test extracts the production queue methods and checks FIFO and wrap,
overflow, bounded processing, packet ownership, concurrent close/reopen,
shutdown, and a producer completing while a simulated controller gate is
held. Run: python3 tests/check_deferred_rx.py. ASan/UBSan are enabled; host leak
inspection is disabled. This is not an IOKit scheduling or hardware test.
The AWDL power test extracts production manager methods and tests timer cancel,
packet ownership, late re-arm/enqueue rejection, powered-only resume and a
concurrent discovery/suspend race. Run: python3 tests/check_awdl_power.py.
GitHub Actions runs both tests, builds the macOS x86_64 kext and checks identity.
These checks cannot establish real hardware sleep reliability.

## Hardware test

1. Keep a bootable EFI backup. Replace only AirPortRTW.kext, then reboot.
2. Confirm the loaded build:

```sh
ioreg -l -w0 | grep -E 'DriverBuild|RX_DEFER_|AWDL_POWER_|PM_(STATE|SLEEP_COUNT|WAKE_COUNT|LAST_SLEEP_RESULT|LAST_WAKE_RESULT)'
```

DriverBuild must be 1.0.2-beta.2-awdl-power-fence. RX_DEFER_QUEUED and
RX_DEFER_PROCESSED should increase during Wi-Fi traffic. RX_DEFER_DROPPED
also includes packets discarded during power transitions.

3. Test normal browsing and download/upload. Toggle Wi-Fi OFF and verify
AWDL_POWER_SUSPENDED = Yes, then ON and verify connectivity returns. Test
several short sleep/wake cycles, followed by the longer sleep that previously failed. Save the above
output before and after, and report the sleep duration and power source.
4. Record the current pmset configuration with pmset -g custom. If background
wake/standby have been disabled, a passing test covers only that setup; repeat
with your original settings later to validate the original trigger.
5. If another panic occurs, provide its complete report and loaded build.
