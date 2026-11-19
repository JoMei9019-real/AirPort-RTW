# AirPort-RTW 1.3.0

This update adds support for Private Wi-Fi Address on compatible macOS setups and improves the connection details shown in macOS.

- **Private Wi-Fi Address.** Use the macOS Wi-Fi settings to choose Fixed, Rotating or Off. On macOS Tahoe with an RTL8821CE, switching to Rotating changed the address shown in macOS and at the router.
- **Open networks.** Fixed a connection issue with open networks on macOS Sequoia.
- **Wi-Fi details.** TX rate, MCS and spatial stream count now use live firmware data. The driver reports 802.11n for HT links and 802.11ac for 5 GHz VHT links. Legacy TX rates display in the correct units.
- **RTL8821C link noise.** macOS can show a noise estimate based on received frames, with a bandwidth-based fallback when a suitable sample is unavailable.
- **Bluetooth coexistence.** Restored periodic firmware checks for Wi-Fi and Bluetooth coexistence. Throughput can vary with the band and Bluetooth activity.

An iPhone Personal Hotspot connection was also tested successfully on Tahoe.

## Update

Extract `AirPortRTW-1.3.0.zip`, replace `AirPortRTW.kext` in your OpenCore setup, and restart. The ZIP includes the kext and `BOOT-ARGS.txt`. Keep the working Wi-Fi dependencies for your macOS version. [Installation guide](https://github.com/JoMei9019-real/AirPort-RTW/blob/v1.3.0/docs/INSTALLATION.md)

## Credits

Thanks to @shammu2bd for testing on the RTL8821CE, reporting the issues and sharing a source patch that helped shape these fixes. [Issue #6](https://github.com/JoMei9019-real/AirPort-RTW/issues/6)
