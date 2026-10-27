# WPA3 cryptographic backend

Pinned SAE import from souissiak1-maker/AirportRTW at
`450fa64d8e758f7180018e5da2f05cab59982fc9`. Vendor sources are unchanged;
`IMPORT.json` and `rtw80211/sae/UPSTREAM.json` verify provenance and content.
See `rtw80211/sae/NOTICE.txt` and the vendor licenses for attribution.

The backend is now linked into the existing driver for 1.2.0 Beta 3.
`src/kext/RTW88WPA3.hpp` supplies the production SAE, key-handshake and PMF
policy. The new frontend/native WCL port remains outside this version.

Run `python3 experimental/wpa3/test_host.py`, or set `SAE_HOST_SANITIZE=1`
for ASan/UBSan. Tests include known crypto answers, two-party SAE, production
four-way exchanges, CCMP known answers and PMF integrity/replay rejection.
See `RELEASE_1_2_0_BETA_3.md` for installation, the experimental native-menu connection path, hardware test instructions and limitations.

The CCMP frame implementation now lives in `src/kext/RTW88WPA3Crypto.cpp`,
compiled separately with scalar-only optimization. `RTW88WPA3AES.hpp` expands
one AES key schedule per frame and uses immutable forward tables. The imported
SAE backend and its provenance manifest remain unchanged. A FIPS-197 vector and
10,000 differential key/block tests validate the bulk AES implementation.
Set `SAE_BENCHMARK=1` for a host CPU-time comparison against the imported AES;
this is not a Wi-Fi throughput prediction. Never enable the reference benchmark
macro in a kernel build.
