# AirPort-RTW 1.2.0 Beta 1 — WPA3-Personal

This beta adds an experimental WPA3-Personal connection path to the existing
IO80211 driver. It keeps the same macOS dependencies as 1.1.0. The native
Sequoia/Tahoe frontend rebuild is deferred to the separate 2.0.0 project.

## Scope

- SAE group 19 (P-256), hunting-and-pecking and H2E; bounded token challenges.
- WPA2/WPA3 transition networks: the helper explicitly selects SAE (AKM 8),
  requires PMF and never falls back to WPA2-PSK. A WPA3-only router mode is not
  required. PSK-only access points are rejected by the WPA3 helper.
- SAE PMK/PMKID, SHA-256 PTK derivation, AES-CMAC four-way/group-key handshakes.
- Required PMF: software CCMP-128, BIP-CMAC-128, management/data replay checks,
  and authenticated SA Query responses.
- Root-only connection helper with private password prompt. Credentials are
  not stored in IORegistry, a configuration file, or the command line.
- Existing WPA2 menu connections, roaming and power handling remain available.

**This is a hardware test build, not a verified interoperable release.** Host
simulation and build checks cannot prove that a Realtek card and a particular
router complete WPA3, DHCP, traffic or sleep/wake successfully.

## Install

Back up the working EFI and retain a recovery path. Replace the existing
AirPortRTW.kext with this build and restart. Keep all currently required legacy
Wi-Fi components/root patches. Do not install a second copy alongside 1.1.0.
OpenCore bundle version is `1.2.0b1`; DriverBuild is `1.2.0-beta.1`.

## Connect to WPA3

The old Apple association interface used by this driver supplies a WPA2 PMK,
not the original password needed for SAE. WPA3 therefore uses the included
helper in this first beta. The normal Wi-Fi password dialog is not yet a WPA3
connection path. A mixed WPA2/WPA3 network joined from that dialog may use WPA2.

1. Disconnect the current Wi-Fi connection while keeping Wi-Fi turned on.
2. Open the Wi-Fi menu to refresh scan results. Obtain the target access point's
   **BSSID** (its six-byte MAC address) from the router or a Wi-Fi scanner.
3. In Terminal, enter the extracted folder and run:

```sh
sudo ./wpa3-connect "Your SSID" aa:bb:cc:dd:ee:ff
```

Enter the password when prompted. A successful submission only starts the
join; it does not mean authentication or DHCP has completed. Check:

```sh
ioreg -r -c AirPortRTW -l | grep -E 'DriverBuild|WPA3(Stage|Error|Active)'
```

Stages: 1 = local commit, 2 = peer commit accepted, 3 = SAE confirmed,
4 = four-way handshake started, 5 = four-way handshake completed.
Stage/error properties refresh with the existing diagnostics timer.
Then check the Wi-Fi interface's DHCP address and test gateway/Internet traffic.

If the helper returns Busy, disconnect first and wait for scanning to finish.
No password is saved. After disconnect, Wi-Fi-off, sleep/wake or reboot, run
it again after refreshing scans. Automatic WPA3 reconnect and roaming are not
implemented in this beta; WPA2 roaming remains available.

## Test and report

Test your WPA2/WPA3 transition network; WPA3-only mode is optional. Verify an incorrect
password fails, a correct password reaches stage 5, DHCP obtains an address,
and traffic works in both directions. Test group rekey and sleep/wake with a
recovery EFI available. Include card model, macOS, router/security mode, stage,
error and observed behavior. Never share passwords or key material.

Software CCMP may reduce throughput and increase CPU usage. This beta does not
claim a packet-loss fix, native unpatched Sequoia/Tahoe support, WPA3-Enterprise,
FT-SAE, SAE-PK, 6 GHz, or AirDrop. Only CCMP-128/BIP-CMAC-128 and group 19 are
supported. Existing sleep/deep-sleep limitations still apply.
