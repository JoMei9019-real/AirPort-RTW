# AirPort-RTW

## 1.1.0 Beta 9: automatic roaming and Neighbor Report diagnostics

RTL8821CE enables automatic WPA2/CCMP roaming by default. The existing controller
timer waits 30 seconds after connection, performs bounded discovery and selects
eligible fresh targets using the established 5 GHz priority and 6 dB same-band
hysteresis. Scans are spaced at least a minute after completion; switching keeps
the 60-second cooldown and one fallback. Manual control pauses automatic actions.
Boot with `-rtwnoautoroam` to disable automatic AP changes; remove it to restore
the personality's default on the next boot. Manual switching remains available.
Neighbor Report rejections now identify parser reason, offset, lengths, token and
timing, with a bounded management-body window at verbose level. Requests refresh
at most once a minute. The association advertises supported 802.11k Neighbor
Reports only; 802.11v BTM remains reject-only and unadvertised. Full measurement,
BTM steering and 802.11r FT are not claimed.
See [Beta 9 installation, behavior and test commands](BETA_1_1_0_9.md).

## 1.1.0 Beta 8: roaming preflight and scan-channel coherence

Beta 8 separates link-state, visibility, authentication cancellation and AWDL
ownership rejection reasons. Explicit roaming returns an AWDL-owned PHY to the
infrastructure channel and verifies the result before continuing; AWDL channel
requests are blocked while a roaming scan or switch owns the PHY. Authentication,
security, freshness and power guards remain active. Scan-cache frequencies follow
the AP's advertised primary channel when present in the enabled regulatory table;
restricted-channel beacon proof still uses the original receive frequency.
See [Beta 8 diagnostics and test procedure](BETA_1_1_0_8.md).
The reported Beta 7 boot panic and successful over-air AP switching remain unconfirmed.

## 1.1.0 Beta 7: scan-based targets, band priority and DFS STA roaming

Beta 7 accepts eligible APs found over the air even when absent from the
Neighbor Report. `--discover` scans enabled 2.4/5 GHz channels with a home-channel
return between slots; `--aps` lists actual BSSIDs. DFS/no-IR channels are scanned
passively and require a fresh matching ESS beacon before a STA roam is allowed.
`--roam-best` prefers usable 5 GHz, falls back to 2.4 GHz and keeps the current AP
when it is preferable. Selection is invoked by the tool, not a background roam
daemon. Artifacts contain the kext, helper and notes directly, with no inner ZIP.
See [Beta 7 commands, selection thresholds and limits](BETA_1_1_0_7.md).

## 1.1.0 Beta 6: repeatable roaming tests and diagnostics

Beta 6 adds runtime Neighbor Report refresh, exact preflight rejection reasons,
a diagnostic scan of one validated non-DFS neighbor channel, and a structured
event timeline through authentication, association, key exchange and fallback.
The bundled tool provides `--prepare`, `--roam`, `--status`, `--watch`, `--report`
and runtime log levels. RTL8821CE personalities enable both roaming switches in
this beta; other cards remain opt-in. No automatic steering or 802.11r FT.
See [Beta 6 commands, limits and test plan](BETA_1_1_0_6.md).

## 1.1.0 Beta 5: controlled WPA2 AP switching

Beta 5 adds an opt-in manual switch to a neighbor verified in the recent scan
cache, using a fresh WPA2-Personal handshake and one fallback attempt. A small
`rtw88-roam` test tool is bundled. Automatic steering and 802.11r FT remain
unimplemented. See [Beta 5 enable switches, limits and test commands](BETA_1_1_0_5.md).

## 1.1.0 Beta 4: experimental 802.11k/v/r foundations

Beta 4 adds opt-in 802.11k Neighbor Report requests and a bounded response cache,
reject-only 802.11v BSS Transition Management handling, and passive 802.11r
Mobility Domain / FT-AKM metadata. It does **not** add automatic AP switching,
802.11r Fast Transition, PMF or WPA3. Active k/v operations default to **off**;
the initial active scope is internal WPA2-Personal/CCMP only.
See [Beta 4 scope, enable switch and test plan](BETA_1_1_0_4.md).
Previous Enterprise, TX batching and stability checks remain; `main` is unchanged.

## 1.1.0 Beta 3: stability regression checks

Beta 3 retains Beta 2's runtime behavior and adds executable workqueue/scan/RX
regression tests plus a compiled x86_64 IOCTL stack-budget gate in CI.
This is test/build hardening, not a new sleep fix or WPA3 implementation.
See [Beta 3 scope and hardware test plan](BETA_1_1_0_3.md).
Deep sleep and live Enterprise interoperability remain unverified;
`main` is unchanged.

## 1.1.0 Beta 2: experimental TX batching

Beta 2 retains Beta 1's unverified WPA2-Enterprise path and adds bounded,
synchronous TX doorbell batching. See [Beta 2 notes and A/B test](BETA_1_1_0_2.md).
No measured throughput improvement is claimed. `main` remains the stable release.

## 1.1.0 Beta 1: experimental WPA2-Enterprise

This `1.0.0-beta` build adds an **unverified experimental** WPA2-Enterprise / 802.1X path on top of 1.0.2 Beta 4. It is not a production release. WPA2-Personal retains its existing internal handshake. See [Beta 1 scope and test instructions](BETA_1_1_0_1.md).

Supported Enterprise scope: CCMP pairwise/group cipher, AKM 00:0f:ac:1, macOS EAP client and an MSK/PMK callback into the existing WPA2 four-way handshake. PMF, WPA3/192-bit/SHA256 Enterprise, PMKSA caching/fast roaming and runtime PEAP/EAP-TLS compatibility are not validated or advertised.


AirPort-RTW is a native macOS IO80211 Wi-Fi driver project derived from the Feixiao rtw88 macOS port.

The goal is to keep Feixiao's Realtek/Linux rtw88 hardware core while replacing the user-controlled network frontend with a native macOS AirPort-style frontend based on IO80211FamilyLegacy and IOSkywalkFamily.

## First integrated target

This branch intentionally delivers the native stack as one larger test unit rather than many reboot-heavy intermediate builds:

- native macOS Wi-Fi interface / menu integration
- scanning
- association
- WPA/WPA2 path
- 2.4 / 5 GHz support
- link state and RX/TX integration
- power-management / sleep-wake hooks
- diagnostics and rtw88 control path retained where useful

Initial PCIe IDs:

- RTL8821CE: 10ec:c821, 10ec:b821
- RTL8822BE: 10ec:b822
- RTL8822CE: 10ec:c822, 10ec:c82f

1.0.2 Beta 4 additionally enables **experimental RTL8814AE** support for `10ec:8813` (some PCI tools call this RTL8813AE). The RTL8814A core, hardware tables and firmware are included, but this macOS integration has not yet been validated on physical RTL8814AE hardware. RTL8812AE remains deferred because it needs a different PCIe transport integration.

See [Beta 4 notes and test plan](BETA_1_0_2_4_RTL8814AE.md). Long sleep/deep sleep is still not guaranteed to work reliably on all systems.

## Dependencies

Run:

```sh
./scripts/bootstrap-deps.sh
```

This checks out:

- AcidAnthera MacKernelSDK
- thegwchr rtw88-stable at `d029a677c49266fad86750714eb5612becd134d3`

The bootstrap script fetches the four required firmware blobs into `firmware/` reproducibly before building.

## Build

```sh
make airport
```

Output:

```
build/out/AirPortRTW.kext
```

The project currently targets x86_64 Hackintosh systems and the Ventura IO80211FamilyLegacy ABI.

## OpenCore setup by macOS version

AirPort-RTW currently targets the Ventura-era IO80211 ABI. The OpenCore setup differs depending on the macOS version.

### macOS Ventura (13)

Ventura already ships the Apple Wi-Fi frameworks that AirPort-RTW targets. Do **not** inject the restored Sonoma+ legacy Wi-Fi stack on Ventura.

1. Copy `AirPortRTW.kext` to `EFI/OC/Kexts/`.
2. Add and enable `AirPortRTW.kext` under OpenCore `Kernel -> Add`.
3. Leave the stock `com.apple.iokit.IOSkywalkFamily` enabled. Do **not** add an OpenCore `Kernel -> Block` entry for it.
4. Do **not** add `IOSkywalkFamily.kext` or `IO80211FamilyLegacy.kext` from the Sonoma/Sequoia/Tahoe compatibility setup.
5. Do not load the old Feixiao `rtw88.kext` at the same time as AirPortRTW; both would match the same PCI device.
6. Reboot and verify that AirPortRTW attaches to the Realtek PCI device and that Wi-Fi appears in macOS.

Lilu and AMFIPass may still be present if your EFI needs them for other patches, but they are not part of the Ventura-specific AirPort-RTW dependency chain described above.

### macOS Sonoma / Sequoia / Tahoe

These releases require the restored legacy Apple Wi-Fi stack.

The required legacy Wi-Fi kexts can be found in the OpenCore Legacy Patcher repository:

[OpenCore-Legacy-Patcher / payloads / Kexts / Wifi](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/main/payloads/Kexts/Wifi)

For AirPort-RTW, the relevant kexts from that folder are:

- `IOSkywalkFamily.kext`
- `IO80211FamilyLegacy.kext`

You do **not** need `IO80211ElCap` or `corecaptureElCap` for the AirPort-RTW setup described here. Use versions that are compatible with your macOS release.

The intended OpenCore load order is:

1. Lilu
2. AMFIPass
3. IOSkywalkFamily
4. IO80211FamilyLegacy
5. AirPortRTW

Block the stock `com.apple.iokit.IOSkywalkFamily` using OpenCore `Kernel -> Block` with Strategy `Exclude` for the applicable Darwin versions. `SecureBootModel` must be configured compatibly with the restored legacy stack.

Do not load the old Feixiao `rtw88.kext` at the same time as AirPortRTW; both would match the same PCI device.

### macOS Monterey and earlier

Monterey and earlier releases are **not currently validated targets** for AirPort-RTW. The project is built around the Ventura IO80211 ABI, so the Ventura instructions should not be assumed to work unchanged on older releases. If support for an older release is added later, its required framework and OpenCore configuration will be documented here.


## Test plan

For the first real hardware test, use one reboot and validate the whole path:

1. confirm AirPortRTW attaches to the Realtek PCI device;
2. verify Wi-Fi appears in macOS;
3. scan and join a WPA2 or WPA2/WPA3-transition network;
4. test normal traffic on 2.4 and 5 GHz;
5. sleep and wake once;
6. switch networks once;
7. collect the diagnostic log if any step fails.

This branch is experimental kernel code. Keep a bootable fallback EFI.


## Lineage and licensing

AirPort-RTW starts from Feixiao and incorporates GPL-compatible native IO80211 work from the RTL88WiFi / AirPort_RTW88 lineage. See `NOTICE.md` and the retained SPDX/copyright notices in individual source files.
