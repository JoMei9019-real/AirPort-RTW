# AirPortRTW 1.3.0 Beta 8

- Corrects the displayed TX PHY rate when firmware uses a legacy OFDM or CCK rate. A 54 Mbit/s OFDM report now displays as 54 Mbit/s.
- Adds an RX-SNR-based noise estimate for the active RTL8821C link using RSSI and SNR from the same frame. Frames must come from the connected AP on its active channel and use the operating channel width. If no plausible sample arrived within five seconds, the driver uses a thermal estimate of −95 dBm at 20 MHz, −92 dBm at 40 MHz or −89 dBm at 80 MHz.
- Keeps scan-list noise at −95 dBm. Beta 7's private Wi-Fi address handling is included.

## Hardware check

While connected on an RTL8821CE, open Wi-Fi details to refresh the noise reading. Check the source during sustained local traffic on 5 GHz, then check again on 2.4 GHz.

```sh
ioreg -r -c AirPortRTW -l -w0 | grep -E '"(DriverBuild|STA_LINK_NOISE_SOURCE)"'
```

`rx-snr` identifies an estimate based on an accepted RX sample. `thermal-estimate` identifies the fallback. `fixed` applies to chips outside the RTL8821C path.

See [issue #6](https://github.com/JoMei9019-real/AirPort-RTW/issues/6) for the community patch and original reports.
