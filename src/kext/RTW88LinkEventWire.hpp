/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include <stdint.h>
#include <stddef.h>

// IO80211FamilyLegacy 1200.12.2b1 (OCLP Wifi payload): setLinkState queries
// selector 156 into 32 bytes, reads byte 16, and writes IEEE reason at 20.
// The SDK declaration instead compiles to 20 bytes (flag at 13, reason at 16).
struct RTW88LinkEventData {
    uint8_t isLinkDown;
    uint8_t pad0[3];
    int32_t rssi;
    uint16_t snr;
    int16_t nf;
    uint8_t cca;
    uint8_t pad1[3];
    // GET 156: voluntary flag. Native event: down && IEEE reason != 8.
    uint8_t flag;
    uint8_t pad2[3];
    uint32_t reason;
    uint8_t reserved[8];
};
struct RTW88LinkEventTLV {
    uint32_t type;
    uint32_t length;
    RTW88LinkEventData data;
};
static_assert(sizeof(RTW88LinkEventData) == 32, "link event data ABI");
static_assert(offsetof(RTW88LinkEventData, rssi) == 4, "link RSSI ABI");
static_assert(offsetof(RTW88LinkEventData, nf) == 10, "link noise ABI");
static_assert(offsetof(RTW88LinkEventData, flag) == 16, "link flag ABI");
static_assert(offsetof(RTW88LinkEventData, reason) == 20, "link reason ABI");
static_assert(sizeof(RTW88LinkEventTLV) == 40, "link event TLV ABI");

inline RTW88LinkEventData rtw88LinkQuery(bool up, bool voluntary, int32_t rssi,
                                        uint32_t downReason) {
    RTW88LinkEventData d = {};
    d.isLinkDown = !up;
    if (!up) { d.flag = voluntary; d.reason = downReason; }
    else { d.rssi = rssi; d.nf = -95; d.snr = rssi > -95 ? rssi + 95 : 0; }
    return d;
}
inline RTW88LinkEventTLV rtw88LinkNotification(bool up, uint32_t ieeeReason) {
    RTW88LinkEventTLV t = {};
    // Native IO80211Interface::setLinkState emits type 14, length 32.
    // postMessage(event 4) extracts this TLV before delivering it to CoreWiFi.
    t.type = 14;
    t.length = sizeof(t.data);
    t.data.isLinkDown = !up;
    t.data.reason = up ? 0 : ieeeReason;
    t.data.flag = !up && ieeeReason != 8;
    return t;
}
