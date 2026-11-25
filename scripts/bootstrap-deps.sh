#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -d .deps/rtl88wifi-reference/.git ]; then
  mkdir -p .deps
  git clone --depth 1 https://github.com/X1REN41L/RTL8821CE-macOS.git .deps/rtl88wifi-reference
fi

rm -rf MacKernelSDK
cp -R .deps/rtl88wifi-reference/driver/RTL88WiFi/MacKernelSDK ./MacKernelSDK

# Fetch only the reviewed PCIe-capable RTL8814A revision.
RTW88_REV=d029a677c49266fad86750714eb5612becd134d3
if [ ! -d rtw88-stable/.git ]; then
  git init -q rtw88-stable
fi
if ! git -C rtw88-stable cat-file -e "$RTW88_REV^{commit}" 2>/dev/null; then
  git -C rtw88-stable fetch --depth=1 https://github.com/vansh101hz-blip/stabler88w.git "$RTW88_REV"
fi
git -C rtw88-stable checkout --detach "$RTW88_REV"

mkdir -p firmware
FW_BASE="https://raw.githubusercontent.com/X1REN41L/RTL8821CE-macOS/main/driver/RTL88WiFi/firmware"
for fw in rtw8821c_fw.bin rtw8822b_fw.bin rtw8822c_fw.bin; do
  if [ ! -s "firmware/$fw" ]; then
    echo "Downloading $fw"
    curl -fL "$FW_BASE/$fw" -o "firmware/$fw"
  fi
done

# Pin and verify the new firmware, including files from an existing checkout.
FW_8814_URL="https://raw.githubusercontent.com/lwfinger/rtw88/a56bcd26e770257612a0803249cbd4095fc6feca/firmware/rtw8814a_fw.bin"
if [ ! -s firmware/rtw8814a_fw.bin ]; then
  curl -fL "$FW_8814_URL" -o firmware/rtw8814a_fw.bin
fi
python3 - <<'FWCHECK'
import hashlib
from pathlib import Path
p = Path("firmware/rtw8814a_fw.bin")
expected = "aa6bf9d62b2d2d8a37254fd6d917ba2839888cdedc21850d4481874cb1d3d7cb"
if hashlib.sha256(p.read_bytes()).hexdigest() != expected:
    raise SystemExit("RTL8814A firmware checksum mismatch; remove the file and bootstrap again")
FWCHECK

echo "Dependencies and firmware ready."
echo "Build with: make airport"
