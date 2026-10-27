# 1.2.0 WPA3 scope and provenance

1.2.0 adds WPA3-Personal to the existing IO80211 frontend. It does not port
WCL/IO80211ControllerV2 or remove legacy Wi-Fi dependencies. That architecture
work belongs to 2.0.0.

The SAE cryptographic backend is imported unchanged from
souissiak1-maker/AirportRTW revision
`450fa64d8e758f7180018e5da2f05cab59982fc9`. Its licenses, vendor revisions and
hashes are retained under `experimental/wpa3/`. The reference V2.2.0 release
targets `2de42fe59cd34d830b3d9fa3ff682ddcf2c504ef`; this import uses main,
not the binary release assets.

The reference also provides SAE/PMF integration in its net80211 stack. Our
backend has a different MLME; `RTW88WPA3.hpp` implements an adapter for the
existing connection path rather than copying the other driver's hardware or
frontend implementation. Existing WPA2 handshake and hardware encryption
paths remain available. WPA3 uses software CCMP/BIP and a native-menu credential decoder to
receive explicitly typed passwords without publishing it to IORegistry.

See [Current beta instructions](../RELEASE_1_2_0_BETA_3.md) for exact scope, tests,
manual connection steps, remaining limitations and hardware verification.
There is no claim that this change fixes packet loss under load. The donor
release also lists sustained throughput, latency and roaming as needing
further testing.
