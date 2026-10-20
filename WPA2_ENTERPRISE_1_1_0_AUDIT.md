# WPA2-Enterprise / 802.1X feasibility audit (candidate 1.1.0)

Base: `1.0.0-beta` at c64dc5a1dd6a1f01c8f548a040a80b0ce94e2c5e.

## Static findings (not a runtime test)

- `src/kext/AirPortRTW.cpp`: `rtw88AssocPayloadLooksValid` (~1524-1540) and `handleASSOCIATE` (~2663-2688) explicitly accept Personal AKMs and require a 32-byte PMK for secured joins. An Enterprise association will be rejected.
- `src/kext/RTW88IEEE80211.cpp`: `rtw88RsnSelectCcmpPsk` and `cmdConnect` (~2780-2816) specialize RSN negotiation to AKM 00:0f:ac:2 (PSK). Enterprise requires AKM 00:0f:ac:1 (802.1X), with correct negotiated RSN IE preserved.
- `processAssocResponse` (~3200-3240) already has an external-supplicant path that exposes LINK_UP for EAPOL and defers data until key installation, but it is not established as functional for Enterprise.
- `handleCIPHER_KEY` (~2783+) and `cmdInstallExternalKey` already provide external PTK/GTK plumbing; confirm lifetime, key flags and controlled-port behavior.
- Internal `handleEAPOL` expects EAPOL-Key frames (minimum 99 bytes); EAP identity/method frames must instead pass unmodified to macOS `eapolclient`, never into the internal PSK state machine.

## Required implementation gates

1. Parse and validate RSN AKM 802.1X, supported pairwise/group cipher, lengths and bounds; distinguish Personal from Enterprise without changing Personal behavior.
2. Permit zero-PMK Enterprise association only when a validated 802.1X AKM is selected, and force the external-supplicant path. Do not accidentally accept arbitrary protected BSS as open.
3. Preserve the negotiated Enterprise RSN IE in association requests; verify LINK_UP/EAPOL delivery and key installation order.
4. Fail closed for unsupported ciphers, missing key material and incomplete handshake. Keep normal data blocked until authorized.
5. Add tests: RSN parser positive/negative fixtures, Personal regression, EAPOL ethertype 0x888e forwarding, PTK/GTK lifecycle, disconnect/reconnect, sleep/wake, and malformed-frame handling.
6. Validate with a controlled WPA2-Enterprise AP and RADIUS (PEAP or EAP-TLS), using redacted logs only. Without this, label the feature experimental and unverified.

## Status

Static audit complete. No functional driver changes, build, hardware tests, or claims of Enterprise compatibility yet. Production branch and existing Personal implementation intentionally untouched.


## Beta 1 implementation follow-up

The experimental implementation is documented in BETA_1_1_0_1.md. Static/host checks do not establish runtime Enterprise compatibility. macOS owns EAP methods; MSK/PMK material feeds the existing internal four-way handshake, rather than two competing key handlers. The original findings above describe the pre-implementation base.
