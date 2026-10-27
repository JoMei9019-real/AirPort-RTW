# Roaming and diagnostics (1.1.0)

The release ZIP does not include the developer tool. To use the commands below,
build `rtw88-roam` from the same source revision as your kext (see
[the build guide](BUILDING.md)). Run commands
from the folder where you extracted it. Normal Wi-Fi use does not require the
tool. Administrative commands use `sudo`.

## How roaming works

Automatic roaming is enabled in the 1.1.0. It evaluates
fresh nearby access points on the same network with compatible security and
allowed channels. A strong 5 GHz connection is preferred; hysteresis and a
60-second switch cooldown reduce repeated back-and-forth switches.

Neighbor Reports are hints, not permission to join an unobserved AP. BTM
suggestions from the AP go through validation, a bounded wait for radio owners
and an acceptance-ACK check before switching. Regular authentication and WPA2
key setup still occur: this is not 802.11r Fast Transition.

Implementation of k/v functions does not mean every optional service is
supported. In particular, AP-initiated accepted BTM switches and detailed
Beacon Measurement interoperability remain incompletely validated.

## Basic checks

```sh
ioreg -r -c AirPortRTW -l | grep DriverBuild
sudo ./rtw88-roam --status
sudo ./rtw88-roam --aps
```

Use `--help` for all commands. Manual switching requires an observed eligible
BSSID (the access point's Wi-Fi address), not just the router's device label.

## Record a test

```sh
sudo ./rtw88-roam --log-level verbose
sudo ./rtw88-roam --watch 300 > ~/Desktop/AirPortRTW-Watch.txt
sudo ./rtw88-roam --report > ~/Desktop/AirPortRTW-After.txt
```

While Watch runs, walk between the APs or run the chosen traffic test. Note
what happened and when. Keep the same location/AP when comparing traffic-load
tests. Check actual Internet access separately from the driver's connection
state. Verbose output can include SSIDs/BSSIDs; redact it before sharing if needed.

To return to normal logging:

```sh
sudo ./rtw88-roam --log-level normal
```

Useful fields:

| Fields | Meaning |
| --- | --- |
| `current_bssid`, `current_channel`, `auto_switches` | Current AP and automatic-switch count |
| `state`, `visible`, `ptk`, `gtk`, `switch_result` | Local connection/key state; not proof of working Internet |
| `neighbor_*` | Neighbor Report requests, responses, freshness and parsing |
| `btm_ingress_*`, `btm_outcome_*` | Latest BTM admission and retained transaction decision |
| `rm_last_*`, `rm_failure_*` | Measurement context and last refused/incapable request |
| `queue_*`, `tx_*` | Output-queue totals/deltas and driver processing counters |
| `wake_*_ms` | First wake milestones relative to driver restore entry; -1 means unobserved |

Counters are cumulative. Compare their increase within a run, not just their
final totals. Queue sampling is periodic, so one interval can begin before
Watch starts. A submitted packet/report or a Wi-Fi ACK does not prove that the
application or AP used its contents successfully.

## Live AWDL-hop comparison

The current build allows changing the policy without rebooting:

```sh
sudo ./rtw88-roam --awdl-hops off
sudo ./rtw88-roam --status | grep awdl_hops_disabled
sudo ./rtw88-roam --awdl-hops on
```

`awdl_hops_disabled=1` means Off. Off returns to the AP channel before
restarting output and prevents AWDL retunes; it does not disable normal
infrastructure scans/roaming or remove the AWDL interface. Cross-channel
AWDL discovery/data may stop. A busy scan/join/measurement rejects the command;
retry after it completes.

Optional boot argument `-rtwnoawdlhop` chooses the initial disabled state.
Runtime commands can override it until reboot; the current policy survives
sleep/wake. Use `awdl_hops_disabled` for the effective state, not the
boot-argument property alone. Automatic roaming can separately be disabled
at boot with `-rtwnoautoroam`.

## Current evidence and remaining work

- Automatic AP switches and 2.4/5 GHz transitions were observed with working
  Internet after switching. Brief traffic interruption is still possible.
- Neighbor Reports, including operating-class-zero hints, were received without
  parser errors/timeouts in the reported tests.
- A router sent Radio Measurement requests and ACKed report frames. Some
  requests were refused/incapable; this does not establish full interoperability.
- Under high traffic, queue drops persist with AWDL hopping disabled. The early
  `outputStart` diagnostic counter stayed at zero on the test system. This
  indicates that the instrumented callback was not exercised, not a proven
  cause of the drops. A short CPU trace showed spare total CPU capacity but
  cannot exclude a single-worker bottleneck.
- High-load TX/queue investigation is planned for 1.1.1 and remains unresolved.
- Wake timing showed a long delay before connection startup in one trace.
  Save a report immediately after wake and another when connectivity returns.

## Experimental Enterprise path

The code contains an unverified WPA2-Enterprise/802.1X path for CCMP and
AKM 00:0f:ac:1, with macOS EAP-client integration and MSK/PMK/key handling.
Host tests are not a successful PEAP/EAP-TLS hardware test. PMF, WPA3,
192-bit/SHA256 Enterprise, PMKSA caching and FT roaming are not advertised
as supported by this release.
