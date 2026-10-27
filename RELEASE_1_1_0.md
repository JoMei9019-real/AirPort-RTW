# AirPortRTW 1.1.0 — release notes draft

**Status: preparation only; 1.1.0 has not been published.**
Based on the development work through `1.1.0-beta.14-tx-flow-control`.
The currently published stable version remains 1.0.2.

## Focus: roaming

The intended 1.1.0 release adds automatic selection between compatible APs,
5 GHz preference with 2.4 GHz fallback, eligible DFS target discovery,
Neighbor Report handling, experimental Beacon Measurements and controlled
802.11v BSS Transition Management. It also includes diagnostics for AP
selection, switch decisions, wake timing and output queues.

Automatic switches and working connectivity after switching have been
observed on the test setup. Short interruptions can occur because 802.11r
Fast Transition is not implemented. Full optional 802.11k/v coverage and
interoperability with every router are not claimed.

## Known limitations to carry into the release

- **High-load output-queue loss is unresolved.** Downloads/speedtests reproduced
  drops even without AWDL hopping or an AP switch. Investigation is deferred
  from 1.1.0 and planned for **1.1.1**; this is not a promise that it is fixed
  in a later build already.
- Wake reconnect can be slow; one measured trace waited about a minute before
  connection startup. Deep sleep/standby/hibernation remain system-dependent
  and not fully validated.
- AP-initiated accepted BTM switches and Beacon Measurement interoperability
  still need hardware validation. Capability labels and ACKed report frames
  do not prove full protocol/application behavior.
- WPA2-Enterprise is experimental and hardware-unverified. WPA3/PMF,
  192-bit/SHA256 Enterprise and 802.11r are not supported claims.
- AirDrop/full Continuity support is not part of the 1.1.0 release promise.
- RTL8814AE remains experimental; RTL8812AE, USB and SDIO are not supported.

The live `--awdl-hops off|on` control is a diagnostic comparison option, not a
fix for the high-load losses. See [roaming and diagnostics](docs/ROAMING.md).

## Installation and update

Use the [OpenCore installation guide](docs/INSTALLATION.md). Existing users
replace the kext, retain the compatible legacy Wi-Fi dependencies and reboot.
Use the helper supplied with the same build. Numeric bundle versions in the
development builds are 1.1.0, but their DriverBuild/description still identify
a beta; this preparation does not change that identity.

## Before actual publication

Set the final driver/build identity and matching CI metadata, build and verify
the final artifact, and publish that artifact with these notes after removing
this draft status. The stable branch, release tag and download must refer to
the same final code. Do not present a beta artifact as the final release.

The publication should retain the high-load and wake limitations above, the
experimental hardware/protocol scope, installation instructions, and credits.
