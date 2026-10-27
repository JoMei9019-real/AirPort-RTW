# AirPort-RTW 1.2.0 Beta 5 — WPA3 roaming

Beta 5 restores the existing roaming features for WPA3-Personal through the
normal macOS Wi-Fi menu. Beta 4's software CCMP optimizations are retained;
the reported peak of 75 Mbit/s does not establish a hardware speed limit.

## Features

- 802.11k Neighbor Reports and passive, active and table Beacon Measurements.
- 802.11v BSS Transition Management (BTM), with checked candidates and an
  acknowledged acceptance before switching.
- Automatic AP selection, 5 GHz preference, signal hysteresis and cooldown.
- Fresh SAE authentication and a new four-way handshake for each WPA3 AP,
  including one bounded return attempt to the previous AP after a failure.

WPA3 targets must offer SAE, CCMP and PMF, including on WPA2/WPA3 transition
networks. A WPA2-only repeater is skipped. Keys from the previous AP are not
reused. Protected management frames are authenticated before processing;
forged or replayed requests are rejected. Encrypted BTM TX completions are
matched using the submitted header identity and CCMP packet number.

SAE needs the password again for a new AP. It is retained only in kernel
memory for the active profile and a pending switch, never written to disk
or diagnostics. Disconnect, power-off, cancellation and teardown erase the
corresponding copies. Sleep/resume and broad interoperability need testing.

## Test and rollback

Keep Beta 4 and a backup of the EFI. Replace the kext, retain the existing
legacy Wi-Fi dependencies/root patches and restart. DriverBuild must show
`1.2.0-beta.5` (bundle `1.2.0b5`, product `1.2.0`).

1. Use two APs with the same SSID/password and WPA3/PMF support.
2. Verify Internet access and WPA3/PMF on the initial AP.
3. Move closer to the other AP and allow a few minutes for discovery and
   cooldown. Confirm the actual BSSID change in the router and Internet access
   afterwards. Record interruptions and check WPA3/PMF on the new AP.
4. Compare throughput with Beta 4 while stationary. Scans and AP switches can
   briefly interrupt traffic. Restore Beta 4 if roaming is unreliable.

```sh
ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|WPA3|ROAM_AUTO|ROAM_K|ROAM_V|ROAM_DIAGNOSTICS'
```

Automatic roaming is enabled by default. `-rtwnoautoroam` disables automatic
and accepted BTM switches; see [the roaming guide](docs/ROAMING.md).
802.11r/FT-SAE is not implemented: full authentication can take several
seconds. These are selected k/v functions, not every optional standard feature.
WPA3 roaming and router interoperability remain unverified on real hardware.

## Validation

Host tests cover fresh SAE/4-way exchanges with another AP, H&P/H2E changes,
old-key rejection, SAE-only candidate selection, 63-byte password transfer,
bounded fallback and secret erasure. Real PMF crypto is exercised together
with production Neighbor Report/RRM/BTM handlers, encrypted acceptance ACK
matching, MIC/replay/source rejection and cancellation. Existing regression,
crypto, sanitizer and macOS bundle checks are required by the beta workflow.
The native frontend rebuild remains reserved for 2.0.0.
