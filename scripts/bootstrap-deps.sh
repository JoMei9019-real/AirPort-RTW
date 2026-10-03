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

echo "Dependencies ready."
echo "Build with: make airport"
