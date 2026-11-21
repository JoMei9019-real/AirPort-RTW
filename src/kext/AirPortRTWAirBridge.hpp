/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

#include <stddef.h>
#include <stdint.h>

class IO80211VirtualInterface;
struct __mbuf;

namespace AirPortRTWAirBridge {
constexpr uint32_t kABIVersion = 1;
constexpr char kABIProperty[] = "AirPortRTWAirBridgeABI";

// Legacy bpfTapInput metadata for AWDL management frames (DLT 12).
struct alignas(8) ActionMetadata {
    uint8_t source[6];
    uint8_t reserved1[6];
    uint32_t channelVersion;
    uint32_t channel;
    uint32_t channelFlags;
    uint8_t reserved2[20];
    int32_t rssi;
    uint8_t reserved3[24];
};
static_assert(sizeof(ActionMetadata) == 72);
static_assert(offsetof(ActionMetadata, channelVersion) == 12);
static_assert(offsetof(ActionMetadata, rssi) == 44);

enum RequestFlag : uint32_t {
    kLocalPeerValid = 1U << 0,
};

struct ActionRequest {
    uint32_t abiVersion;
    uint32_t size;
    IO80211VirtualInterface *vif;
    __mbuf *packet;
    ActionMetadata *metadata;
    uint64_t handoffUS; // Monotonic clock sampled on the controller workloop.
    uint32_t flags;
    uint32_t reserved;
};
static_assert(sizeof(ActionRequest) == 48);

enum ResultFlag : uint32_t {
    kNativeObserved = 1U << 0,
    kNativeProcessed = 1U << 1,
    kNativePeerLookup = 1U << 2,
    kNativePeerMatched = 1U << 3,
};

struct ActionResult {
    uint32_t appleResult;
    uint32_t flags;
};
static_assert(sizeof(ActionResult) == 8);

struct ActionCounters {
    uint32_t observed = 0;
    uint32_t processed = 0;
    uint32_t peerLookups = 0;
    uint32_t peersMatched = 0;

    void record(uint32_t flags)
    {
        if (!(flags & kNativeObserved)) return;
        ++observed;
        if (!(flags & kNativeProcessed)) return;
        ++processed;
        if (!(flags & kNativePeerLookup)) return;
        ++peerLookups;
        if (flags & kNativePeerMatched) ++peersMatched;
    }
};
} // namespace AirPortRTWAirBridge

// Kernel-only interception point. Call the original once per request. Every
// pointer is borrowed for this synchronous call; the caller frees the packet.
extern "C" void rtw88_airbridge_action_v1(
    const AirPortRTWAirBridge::ActionRequest *request,
    AirPortRTWAirBridge::ActionResult *result);
