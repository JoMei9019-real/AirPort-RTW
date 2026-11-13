/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace RTW88StationMACWire {

// IO80211FamilyLegacy 1200.12.2b1, getHwMacAddr/setPrivateMacAddress.
constexpr int HardwareAddressSelector = 0x167;
constexpr int SetAddressSelector = 0x170;

struct HardwareAddress {
    uint32_t version;
    uint8_t address[6];
    uint8_t padding[2];
};

// IO80211FamilyLegacy 1200.12.2b1 transports 28 bytes. AirPortBrcmNIC
// 1400.1.1 reads enable, flags, timeout and the address at these offsets.
struct PrivateMAC {
    uint32_t version;
    uint32_t enabled;
    uint32_t flags;
    uint32_t timeoutSeconds;
    uint8_t address[6];
    uint8_t unused[6];
};

static_assert(sizeof(HardwareAddress) == 12 && offsetof(HardwareAddress, address) == 4,
              "HW_ADDR payload layout changed");
static_assert(sizeof(PrivateMAC) == 28 && offsetof(PrivateMAC, enabled) == 4 &&
              offsetof(PrivateMAC, flags) == 8 && offsetof(PrivateMAC, timeoutSeconds) == 12 &&
              offsetof(PrivateMAC, address) == 16, "PRIVATE_MAC payload layout changed");

} // namespace RTW88StationMACWire
