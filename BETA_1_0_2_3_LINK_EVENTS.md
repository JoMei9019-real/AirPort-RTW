# AirPortRTW 1.0.2-beta.3: native link events and wake reconnect

DriverBuild: **1.0.2-beta.3-link-events-reconnect**. Bundle/kmod version stays
**1.0.2**. Based only on 1.0.2 Beta 2 on `1.0.0-beta`; retains deferred RX and
AWDL power fencing. No merge from the 2.0.0 branch.

## Verified ABI evidence

The USB fork's [patch 0004](https://github.com/kodeaqua/AirPort-RTW-USB/blob/30022a524503e64baae65d984dc3e2c88448b15c/patches/0004-link-changed-payload.patch)
identified an empty `LINK_CHANGED` payload but used an untested bare 32-byte
buffer. This build instead follows the actual native family's format.

Inspected [OCLP IO80211FamilyLegacy-v1.0.0.zip](https://github.com/dortania/OpenCore-Legacy-Patcher/tree/main/payloads/Kexts/Wifi):
bundle **1200.12.2b1**, UUID **4C07538B-62EB-3D6D-AEF9-93BCDCF45FAB**,
the same UUID as the user's supplied panic. Binary SHA-256:
`ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894`.

- `IO80211Interface::setLinkState` at unslid `0x9859c` zeros 32 bytes
  and requests selector 156 (`LINK_CHANGED_EVENT_DATA`) at `0x9860c-0x98633`.
  It reads the down flag at byte 0 and the voluntary query flag at byte 16.
- Its event builder at `0x989b4-0x98a46` zeros 32 bytes, writes the IEEE
  reason at byte 20 and the native event flag at byte 16, then wraps the data
  in a **type 14, length 32 TLV**, passing **40 bytes** to `postMessage(4)`.
  The event flag is `linkDown && reason != 8`; it is not the GET's voluntary flag.
- `postMessage(4)` dispatches to `0x96d09`, extracts TLV type 14 at
  `0x96ebb-0x96ecd`, and checks for exactly 32 extracted bytes at `0x96ed8`.
  Bare data does not satisfy this TLV contract.
- The project's SDK declaration has misleading offset comments: on x86_64
  its actual size is 20, voluntary at 13, reason at 16. The fixed GET now
  fills the full 32-byte wire layout, including zeroed reserved bytes.

The native family still emits its own events from `setLinkState`. Existing
explicit disconnect notifications now also use the correct TLV wrapper.
This does not alter the AWDL virtual-interface event ABI.

## Reconnect changes and limits

- Track voluntary host disconnect/Wi-Fi OFF separately from AP deauth and
  join failure. Report it at the native GET's byte-16 offset; do not infer
  voluntary status solely from an IEEE reason code that an AP can also send.
- After successful firmware restore, clear old frontend scan/cursor and
  association-completion state before synchronous CoreWiFi callbacks.
- Open the PM fence and mark the controller ON before posting the typed
  down-link event and then POWER_CHANGED. Emit the extra wake link event
  only for an actually powered radio; preserve Wi-Fi left OFF.
- Reset wake-readiness diagnostics at wake entry; report actual radio power.

CoreWiFi remains responsible for choosing and joining a saved network. No
credential replay, retry timer, new DRIVER_AVAILABLE ABI guess or forced
power-off is added. Hardware auto-join is **not yet confirmed**. In particular,
the USB fork's error 37 has not been demonstrated or diagnosed on this PCIe
machine; this build does not claim to fix every cause of that error.

## Checks

`python3 tests/check_link_events.py` runs the actual production event-posting
and wake methods with synchronous callback stubs under ASan/UBSan. Covers
32-byte GET bounds/canaries, byte offsets, TLV extraction, voluntary/AP
disconnect data, ready-before-callback ordering, stale scan clearing,
radio-OFF preservation, and failed firmware/DMA restore fencing. Native macOS
CI also runs the RX and AWDL power tests and builds the x86_64 kext.

## Hardware test

Replace the old kext, reboot and verify the build. Connect to a saved WPA2
network. Test several short sleeps, then the longer sleep that previously
failed. After wake, wait 30 seconds without manually joining or toggling Wi-Fi.
Also test an unexpected AP restart and Wi-Fi deliberately OFF before sleep.

```sh
ioreg -l -w0 | grep -E 'DriverBuild|STA_LINK_(EVENT|QUERY)|PM_(STATE|WAKE|LAST)|STA_V23_NATIVE_(ERROR|SET_ERROR)|RX_DEFER_|AWDL_POWER_'
/usr/bin/log show --last 5m --info --debug --predicate 'process == "airportd"' > ~/airportd-beta3.txt
sudo dmesg > ~/dmesg-beta3.txt
```

Expected custom event sizes: `STA_LINK_EVENT_TLV_BYTES=40`,
`STA_LINK_EVENT_DATA_BYTES=32`, `STA_LINK_QUERY_BYTES=32` when queried.
Check whether the LINK_CHANGED payload-length warning disappears and whether
macOS auto-joins. Other warnings such as BSSID_CHANGED must be checked
separately. Report time to reconnect, radio state, and any remaining error 37.
Deep sleep and AirDrop are not established by these host/build checks.
