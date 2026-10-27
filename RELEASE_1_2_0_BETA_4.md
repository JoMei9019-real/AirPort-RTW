# AirPort-RTW 1.2.0 Beta 4 — WPA3 processing efficiency

Beta 3's first follow-up test reached about 60 Mbit/s in both directions,
but reported CPU power increasing from 9 W to 18 W during traffic. WPA3
still encrypts and authenticates data in software, which adds CPU work.
Those power readings alone do not isolate the cost of encryption from
network processing, radio activity and the speed-test application.

## What changed

- Process payload encryption and authentication in one combined pass.
- Interleave two independent AES blocks so the CPU can overlap their work.
- Precompute the scalar AES table rotations at build time and use full-block
  word operations; handle the last partial block separately.

The aim is less CPU work per byte. A GCC development-host comparison against
Beta 3's exact crypto source measured about 2x faster processing, using three
alternating runs of 100,000 1,500-byte frames and scalar-only compiler flags.
Host results vary. This is a synthetic CPU-time comparison, not a prediction
of your Wi-Fi speed or a measurement of power savings. Beta 4's throughput
and power consumption still need a hardware test.

WPA3/SAE selection on transition networks, PMF, MIC validation and replay
checks remain active. The imported SAE sources, key handling, radio settings
and driver optimization flags are unchanged. There is no hardware crypto
offload or SIMD/FPU/AES-NI code in this beta. Legacy Wi-Fi dependencies remain
required; the frontend rebuild is reserved for 2.0.0.

## Validation

- AES known answer and 10,000 differential keys, including paired and
  in-place block operations.
- 54 independent PyCA AESCCM answers covering data/QoS/management frames,
  zero-length and partial blocks, 1,500-byte and 8 KiB payloads, unaligned
  buffers and tampered payloads, headers and tags.
- Existing SAE, transition-network handshake, PMF integrity/replay and
  native-menu credential tests under ASan/UBSan.
- Existing driver regressions, macOS bundle/link checks and inspection for
  SIMD register use and dynamic table initialization in the crypto object.

## Install and compare

Keep Beta 3 and a backup of your working EFI for rollback. Replace the kext,
keep your existing dependencies/root patches and restart. The loaded
`DriverBuild` should be `1.2.0-beta.4` (bundle `1.2.0b4`, product `1.2.0`).

Connect from the macOS Wi-Fi menu. Compare with Beta 3 on the same AP, Wi-Fi
band, location and test server. Check that the router still reports WPA3/PMF.
Measure download/upload, CPU use and power both at idle and during the same
workload; a fixed-rate transfer is more useful for efficiency comparisons
than maximum-speed tests moving different amounts of data.

```sh
ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|WPA3'
```

`WPA3CCMP` identifies this path as `software-paired-scalar-aes`. Diagnostics
contain no passwords or keys. Automatic WPA3 roaming/reconnect and broad
card/router compatibility remain unverified. No universal heavy-load
packet-loss fix, WPA3-Enterprise, FT-SAE or AirDrop support is claimed.
