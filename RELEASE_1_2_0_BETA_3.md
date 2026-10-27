# AirPort-RTW 1.2.0 Beta 3 — WPA3 software CCMP performance

The first reported hardware test of Beta 2 connected through the macOS menu
using WPA3/PMF, but download/upload were only about 5/6 Mbit/s. This verifies
that user's menu/SAE path; it does not certify every card/router combination.

## Changes

- Reuse an AES key schedule for all blocks of a CCMP frame, rather than
  expanding the key again for every 16-byte block.
- Replace the bulk path's generic AES round arithmetic with an immutable
  scalar forward table. The imported SAE crypto backend is unchanged.
- Move bulk CCMP to a separate optimized translation unit. Beta 2's C++ frame
  loop used the driver's default unoptimized flags. Only this pure crypto
  file changes optimization; the IOKit, lifecycle and radio build flags stay
  unchanged. SIMD/FPU/AES-NI are not required or used by the new kernel object.
- Publish `WPA3CCMP`, `WPA3TxAggregation` and `WPA3ChannelWidthMHz` alongside
  the existing metadata diagnostics.

SAE selection, PMF, authentication tags and replay checks remain in place.
There is no WPA2 fallback for SAE-capable transition networks and no switch
to the hardware security CAM in this beta. WPA2-only networks retain their
existing path. Legacy Wi-Fi dependencies are still required; the new native
frontend remains deferred to 2.0.0.

## Validation and limits

Tests include a FIPS-197 AES answer, 10,000 differential keys/blocks against
the pinned reference, in-place operation, the independent AES-CCM answer,
SAE/transition handshakes and PMF integrity/replay rejection, with ASan/UBSan.

A same-host CPU-time microbenchmark of 1,500-byte CCMP frames measured roughly
167/196 Mbit/s encrypt/decrypt for the new AES versus 35/34 Mbit/s for the
reference AES in the same optimized wrapper. These are illustrative CPU
measurements, not predicted Wi-Fi speeds or a measurement of the old binary.
The host can vary. Real throughput, latency, CPU usage and rekey/power behavior
must still be tested on the card. This is not a claim that all heavy-load
packet loss or every performance bottleneck is fixed.

## Install and compare

Back up the working EFI and keep Beta 2 for rollback. Replace AirPortRTW.kext,
retain existing dependencies/root patches and restart. DriverBuild should be
`1.2.0-beta.3`, bundle version `1.2.0b3`, product version `1.2.0`.

Connect through the normal Wi-Fi menu to the same WPA2/WPA3 transition AP.
No helper application is included. Compare speed with the same AP, band,
location and test server as Beta 2. Verify the router still reports WPA3/PMF.
If performance remains low, collect after the test:

```sh
ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|WPA3|RADIO_(RSSI|CHANNEL|WIDTH|TX_AGGREGATION)'
```

Please include measured download/upload and the Wi-Fi band/channel. Router
STBC/TxBF/MU-MIMO capability labels alone do not measure the active data rate.
No passwords or keys are included in these diagnostic properties.

The Beta 2 native-menu credential limitations still apply on untested systems;
see `RELEASE_1_2_0_BETA_2.md` in the source. Automatic WPA3 reconnect/roaming and
broad hardware compatibility remain unverified. No WPA3-Enterprise, FT-SAE,
SAE-PK, 6 GHz or AirDrop support is added.
