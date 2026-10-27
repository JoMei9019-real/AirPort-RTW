# AirPort-RTW 1.0.1

Maintenance release fixing a sleep-transition deadlock found after 1.0.0.

## Fixed
- Prevented NAPI work from requeueing indefinitely while the driver is being stopped for system sleep.
- Fixes a sleep timeout that could end in a kernel panic after 180 seconds.
- Avoids the machine remaining powered on and heating up while macOS waits for the network power-state callback to finish.

## Included from 1.0.0
- Native macOS Wi-Fi integration through IO80211FamilyLegacy
- RTL8821CE verified
- RTL8822BE / RTL8822CE supported and awaiting broader hardware reports
- WPA2-Personal
- WPA2/WPA3 transition networks using WPA2
- Open networks
- 2.4 GHz and 5 GHz
- Native scanning and association
- CoreWiFi auto-join
- Sleep/wake reconnect path
