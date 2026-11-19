// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace RTW88AWDL {
// IO80211FamilyLegacy 1200.12.2b1, x86_64. AirPortBrcmNIC supplies one
// request per callback. Legacy overwrites the budgets with actual counts.
template<class Packet> struct PeerTxRequest {
    uint16_t flags, total, unicast, multicast;
    uint16_t counts[8];
    Packet heads[8];
    uint16_t mask;
    uint16_t reserved[3];

    void prepare(unsigned options, unsigned space) {
        // Reserve at most one batch across all the requested traffic classes.
        unsigned remaining = space;
        mask = options & 15;
        // Bonjour and NDP multicast must also progress with one free slot.
        if (options & 16) {
            multicast = remaining < 8 ? remaining : 8;
            remaining -= multicast;
        }
        for (unsigned i = 0; i < 4; ++i) {
            if (!(mask & (1U << i))) continue;
            counts[i] = remaining < 8 ? remaining : 8;
            unicast += counts[i];
            remaining -= counts[i];
        }
        total = unicast + multicast;
    }
};
using PeerTxLayout = PeerTxRequest<void *>;
static_assert(sizeof(PeerTxLayout) == 0x60, "Legacy packet request size");
static_assert(offsetof(PeerTxLayout, heads) == 0x18 && offsetof(PeerTxLayout, mask) == 0x58,
              "Legacy packet request offsets");
}
