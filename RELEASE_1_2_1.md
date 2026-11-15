# AirPort-RTW 1.2.1

This update fixes a driver bug that could stop internet traffic during a large
download while macOS still showed Wi-Fi as connected.

Normal traffic and background scans could try to use the same slot in the Wi-Fi
card's transmit queue. The driver now protects the slot from selection until
the packet is queued.

Replace the existing `AirPortRTW.kext` in your OpenCore setup and restart.
The ZIP contains the kext and `BOOT-ARGS.txt`. The fix works with the default
settings and requires no additional boot arguments.
