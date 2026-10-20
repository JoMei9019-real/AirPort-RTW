/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Pure, bounded RSN validation shared by the ioctl and MLME paths. */
namespace RTW88Enterprise {
constexpr uint32_t Ccmp = 0x000fac04, Tkip = 0x000fac02;
constexpr uint32_t Psk = 0x000fac02, Dot1x = 0x000fac01;
/* The Ventura SDK stops at PMKSA; later Apple headers define MSK as 9.
 * apple80211_key carries the first 32 bytes of MSK (the WPA2 PMK). */
constexpr uint32_t AppleMsk = 9;
struct Rsn {
    uint32_t group = 0;
    uint16_t pairwiseCount = 0, akmCount = 0, caps = 0, pmkids = 0;
    bool ccmp = false, psk = false, dot1x = false, groupMgmt = false;
};
inline uint16_t le16(const uint8_t *p) { return p[0] | (uint16_t(p[1]) << 8); }
inline uint32_t suite(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | p[3];
}
inline bool parse(const uint8_t *p, size_t n, Rsn &out) {
    out = {};
    if (!p || n < 8 || le16(p) != 1) return false;
    out.group = suite(p + 2);
    out.pairwiseCount = le16(p + 6); p += 8; n -= 8;
    if (!out.pairwiseCount || out.pairwiseCount > n / 4) return false;
    for (unsigned i = 0; i < out.pairwiseCount; ++i, p += 4, n -= 4)
        out.ccmp |= suite(p) == Ccmp;
    if (n < 2) return false;
    out.akmCount = le16(p); p += 2; n -= 2;
    if (!out.akmCount || out.akmCount > n / 4) return false;
    for (unsigned i = 0; i < out.akmCount; ++i, p += 4, n -= 4) {
        out.psk |= suite(p) == Psk;
        out.dot1x |= suite(p) == Dot1x;
    }
    if (!n) return true;
    if (n < 2) return false;
    out.caps = le16(p); p += 2; n -= 2;
    if (!n) return true;
    if (n < 2) return false;
    out.pmkids = le16(p); p += 2; n -= 2;
    if (out.pmkids > n / 16) return false;
    p += 16 * out.pmkids; n -= 16 * out.pmkids;
    if (!n) return true;
    if (n != 4) return false;
    out.groupMgmt = true;
    return true;
}
inline bool selectedDot1x(const uint8_t *ie, size_t n) {
    Rsn r;
    return ie && n >= 2 && n <= 257 && ie[0] == 48 && size_t(ie[1]) + 2 == n &&
        parse(ie + 2, n - 2, r) && r.ccmp && r.dot1x &&
        r.group == Ccmp && r.pairwiseCount == 1 && r.akmCount == 1 &&
        !(r.caps & 0x00c0) && !r.pmkids && !r.groupMgmt;
}
inline bool eapol(const uint8_t *p, size_t n, uint8_t &type) {
    if (!p || n < 4 || p[0] < 1 || p[0] > 3 || p[1] > 3) return false;
    const size_t body = (size_t(p[2]) << 8) | p[3];
    if (body > n - 4) return false;
    type = p[1];
    return true;
}
inline bool dataAllowed(bool enterprise, bool authorized, uint16_t etherType) {
    return !enterprise || authorized || etherType == 0x888e;
}
enum class Auth { Invalid, Open, Personal, Enterprise };
inline Auth auth(uint32_t lower, uint32_t upper, uint32_t keylen,
                 const uint8_t *ie, size_t capacity) {
    if (lower != 1) return Auth::Invalid; // Apple OPEN authentication
    if (!upper) return keylen ? Auth::Invalid : Auth::Open;
    constexpr uint32_t personal = (1u << 1) | (1u << 3) | (1u << 7);
    constexpr uint32_t enterprise = (1u << 2) | (1u << 5);
    if ((upper & enterprise) && !(upper & personal)) {
        if ((upper & ~(enterprise | 1u)) || keylen || !ie || capacity < 2)
            return Auth::Invalid;
        size_t n = size_t(ie[1]) + 2;
        return n <= capacity && selectedDot1x(ie, n) ? Auth::Enterprise : Auth::Invalid;
    }
    if ((upper & personal) && !(upper & ((1u << 5) | (1u << 8))))
        return keylen == 32 ? Auth::Personal : Auth::Invalid;
    return Auth::Invalid;
}
} // namespace RTW88Enterprise
