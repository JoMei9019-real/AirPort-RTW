# Building AirPort-RTW

Building is intended for developers on macOS with Xcode Command Line Tools.
Users installing the driver can use prebuilt release downloads instead.

From the repository root:

```sh
./scripts/bootstrap-deps.sh
make airport
```

The kext is written to `build/out/AirPortRTW.kext`. The bootstrap script obtains
MacKernelSDK, the pinned Linux rtw88 hardware core and required firmware.
The firmware is embedded in the resulting bundle.

The build currently targets x86_64 and the Ventura-era IO80211FamilyLegacy ABI.
The scripts and Makefile are authoritative for dependency revisions and compiler
flags; do not substitute a different hardware-core revision without validation.

The stable workflow builds and inspects the kext and runs RX ownership,
AWDL power-fencing and link/wake regression checks from `tests/`.
Additional roaming tools and checks live on the `1.0.0-beta` development branch.
Host mocks do not validate RF interoperability.

Preserve the SPDX/copyright notices and the acknowledgements in
[NOTICE.md](../NOTICE.md) when redistributing source or builds.
