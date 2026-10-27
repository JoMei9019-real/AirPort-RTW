# AirPort-RTW 1.2.0 Beta 2 — native WPA3 menu test

This build connects the WPA3 engine to the existing macOS Wi-Fi menu request
path. No separate connection application is included or required by the new
path. The driver still uses IO80211FamilyLegacy and needs the same macOS
components/root patches as the working 1.1.0 setup. The native frontend
rebuild remains reserved for 2.0.0.

**This is an experimental menu-integration test, not a verified working native
WPA3 release.** The driver can now accept explicitly typed passphrases from
native association requests. Whether macOS actually supplies that request
with the restored legacy frontend is not established by host tests or a
successful kernel build. A hardware menu-join test is required.

## What changed

- Advertise SAE and PMF capabilities and route typed-password association
  requests to SAE on the existing frontend.
- The Sequoia/Tahoe host request decoder now accepts explicit password cipher
  type 10 and SAE auth, including bounded 1–63-byte key slots; the legacy typed
  structure is limited to its actual 32-byte key capacity.
- Reject PMK-only SAE requests rather than treating a WPA2 key as a password.
- Prefer SAE on a WPA2/WPA3 transition AP when a passphrase arrives. Refuse a
  PMK-only WPA2 join on a scanned SAE-capable transition AP, preventing a silent
  downgrade. A WPA3-only router mode is not required.
- Keep the tested SAE/PMF engine from Beta 1, with software CCMP/BIP.

The extended password-slot interpretation and capability delivery on the old
family remain experimental. Unknown/truncated envelopes are rejected; no
unbounded reads or guessed kernel pointers are used. Password bytes are wiped
from driver-owned temporary buffers and never published as diagnostics.

## Install and test

1. Back up the working EFI and retain a recovery boot path.
2. Replace AirPortRTW.kext with this build, keeping required legacy Wi-Fi
   components. Restart. DriverBuild should be `1.2.0-beta.2`; OpenCore bundle
   version is `1.2.0b2`, product version `1.2.0`.
3. Select your WPA2/WPA3 network from the normal Wi-Fi menu. Enter its password
   if macOS prompts. A saved WPA2 PMK may be insufficient; use macOS's normal
   Forget This Network flow and rejoin if you want to test fresh password entry.
4. Check the metadata-only diagnostics:

```sh
ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|WPA3|STA_ASSOC_INPUT_AUTH_UPPER|STA_ASSOC_INPUT_KEY_LEN'
```

`WPA3_MENU_HOST_PASSWORD = Yes` means the host envelope delivered an explicitly
password-typed request. `WPA3_MENU_STATUS = sae-request-accepted` means it was
submitted to SAE; it does not yet mean authentication succeeded.

`password-not-delivered` or `pmk-only-transition-refused` means the native path
supplied no usable SAE password. That result identifies a remaining Apple
frontend integration problem, not proof that your router rejects WPA3. There
is deliberately no WPA2 fallback on that transition AP in this test build.
Return to your working driver if you need the previous WPA2 transition behavior.

Stages: 1 = local SAE commit, 2 = peer commit accepted, 3 = SAE confirmed,
4 = four-way handshake started, 5 = four-way handshake completed. Then verify
DHCP obtains an address and test gateway/Internet traffic in both directions.
Include card model, macOS, router mode and these metadata fields in a report.
Never share passwords or key material.

Automatic WPA3 reconnect/roaming, group rekey and sleep/wake need hardware
validation. Software CCMP can reduce throughput and increase CPU use. There
is no claim of a packet-loss fix, WPA3-Enterprise, FT-SAE, SAE-PK, 6 GHz or
AirDrop. WPA2-only networks continue to use the existing WPA2 path.
