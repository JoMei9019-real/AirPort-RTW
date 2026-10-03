#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -d MacKernelSDK/.git ]; then
  git clone https://github.com/acidanthera/MacKernelSDK.git MacKernelSDK
fi

if [ ! -d rtw88-stable/.git ]; then
  git clone https://github.com/thegwchr/rtw88-stable.git rtw88-stable
fi

mkdir -p firmware
FW_BASE="https://raw.githubusercontent.com/X1REN41L/RTL8821CE-macOS/main/driver/RTL88WiFi/firmware"
for fw in rtw8821c_fw.bin rtw8822b_fw.bin rtw8822c_fw.bin; do
  if [ ! -s "firmware/$fw" ]; then
    echo "Downloading $fw"
    curl -fL "$FW_BASE/$fw" -o "firmware/$fw"
  fi
done

echo "Dependencies and firmware ready."
echo "Build with: make airport"
