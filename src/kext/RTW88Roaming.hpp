/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "RTW88Enterprise.hpp"

/* Bounded wire helpers only. Reports are hints, never trusted roam targets.
 * No FT keys, security negotiation, channel switches or heap allocations. */
namespace RTW88Roaming {
constexpr size_t MaxCandidates = 16;
constexpr size_t MaxActionBytes = 1024;
constexpr uint64_t ResponseTimeoutMs = 5000, CandidateLifetimeMs = 30000;
struct Capabilities {
    bool neighborReport = false, btm = false, mobilityDomain = false, pmfRequired = false;
    uint16_t mdid = 0;
    uint8_t ftPolicy = 0, ftAkms = 0; // bit 0: FT-802.1X, bit 1: FT-PSK
};
struct Candidate {
    uint8_t bssid[6] = {}, opClass = 0, channel = 0, phy = 0;
    uint32_t info = 0;
    bool hasPreference = false;
    uint8_t preference = 0;
};
struct Candidates {
    Candidate entries[MaxCandidates] = {};
    uint8_t count = 0;
    bool truncated = false;
};
struct BtmRequest {
    uint8_t token = 0, mode = 0, validity = 0;
    uint16_t disassociationTimer = 0;
    Candidates candidates;
};
inline bool unicast(const uint8_t *mac) {
    uint8_t value = 0;
    for (unsigned i = 0; i < 6; ++i) value |= mac[i];
    return value && !(mac[0] & 1);
}
inline bool capabilities(const uint8_t *p, size_t n, Capabilities &out) {
    out = {};
    if ((!p && n) || n > 512) return false;
    Capabilities result;
    bool rrm = false, ext = false, md = false, rsnSeen = false;
    while (n) {
        if (n < 2 || p[1] > n - 2) return false;
        const uint8_t id = p[0], len = p[1];
        const uint8_t *v = p + 2;
        if (id == 70) {
            if (rrm || len != 5) return false;
            rrm = true; result.neighborReport = (v[0] & 2) != 0;
        } else if (id == 127) {
            if (ext) return false;
            ext = true; result.btm = len >= 3 && (v[2] & 8);
        } else if (id == 54) {
            if (md || len != 3) return false;
            md = true; result.mobilityDomain = true;
            result.mdid = RTW88Enterprise::le16(v); result.ftPolicy = v[2] & 3;
        } else if (id == 48) {
            RTW88Enterprise::Rsn rsn;
            if (rsnSeen || !RTW88Enterprise::parse(v, len, rsn)) return false;
            rsnSeen = true;
            result.pmfRequired = (rsn.caps & 0x40) != 0;
            size_t offset = 10 + size_t(rsn.pairwiseCount) * 4;
            for (unsigned i = 0; i < rsn.akmCount; ++i, offset += 4) {
                const uint32_t akm = RTW88Enterprise::suite(v + offset);
                if (akm == 0x000fac03) result.ftAkms |= 1;
                if (akm == 0x000fac04) result.ftAkms |= 2;
            }
        }
        p += size_t(len) + 2; n -= size_t(len) + 2;
    }
    out = result; return true;
}
inline bool candidateIEs(const uint8_t *p, size_t n, Candidates &out) {
    out = {};
    if ((!p && n) || n > MaxActionBytes) return false;
    Candidates result;
    while (n) {
        if (n < 2 || p[1] > n - 2) return false;
        size_t len = p[1];
        if (p[0] == 52) {
            if (len < 13) return false;
            const uint8_t *v = p + 2;
            Candidate c;
            memcpy(c.bssid, v, 6);
            if (!unicast(c.bssid) || !v[10] || !v[11]) return false;
            c.info = uint32_t(v[6]) | (uint32_t(v[7]) << 8) |
                     (uint32_t(v[8]) << 16) | (uint32_t(v[9]) << 24);
            c.opClass = v[10]; c.channel = v[11]; c.phy = v[12];
            for (size_t pos = 13; pos < len;) {
                if (len - pos < 2 || v[pos + 1] > len - pos - 2) return false;
                if (v[pos] == 3) {
                    if (v[pos + 1] != 1 || c.hasPreference) return false;
                    c.hasPreference = true; c.preference = v[pos + 2];
                }
                pos += size_t(v[pos + 1]) + 2;
            }
            bool duplicate = false;
            for (unsigned i = 0; i < result.count; ++i)
                duplicate |= memcmp(result.entries[i].bssid, c.bssid, 6) == 0;
            if (!duplicate) {
                if (result.count < MaxCandidates) result.entries[result.count++] = c;
                else result.truncated = true;
            }
        }
        p += len + 2; n -= len + 2;
    }
    out = result; return true;
}
inline bool neighborResponse(const uint8_t *p, size_t n, uint8_t token, Candidates &out) {
    out = {};
    return p && n >= 3 && n <= MaxActionBytes && p[0] == 5 && p[1] == 5 &&
        token && p[2] == token && candidateIEs(p + 3, n - 3, out);
}
inline bool btmRequest(const uint8_t *p, size_t n, BtmRequest &out) {
    out = {};
    if (!p || n < 7 || n > MaxActionBytes || p[0] != 10 || p[1] != 7 ||
        (p[3] & 0xe0)) return false;
    BtmRequest result;
    result.token = p[2]; result.mode = p[3];
    result.disassociationTimer = RTW88Enterprise::le16(p + 4);
    result.validity = p[6]; p += 7; n -= 7;
    if (result.mode & 8) { // BSS Termination Duration subelement
        if (n < 12 || p[0] != 4 || p[1] != 10) return false;
        p += 12; n -= 12;
    }
    if (result.mode & 16) { // Session Information URL: never fetched or logged
        if (!n || p[0] > n - 1) return false;
        size_t length = size_t(p[0]) + 1; p += length; n -= length;
    }
    if (!candidateIEs(p, n, result.candidates)) return false;
    out = result; return true;
}
inline bool actionFromAP(const uint8_t *frame, size_t n,
                         const uint8_t *local, const uint8_t *ap) {
    if (!frame || !local || !ap || n < 26 || n > 24 + MaxActionBytes) return false;
    const uint16_t fc = RTW88Enterprise::le16(frame);
    // No fragmentation, DS, protected/encrypted or HT-control payloads in this
    // unprotected WPA2 test path. PMF needs a separate verified RX path.
    return (fc & 0xc7ff) == 0x00d0 && (frame[22] & 15) == 0 &&
        unicast(ap) && unicast(local) && !memcmp(frame + 4, local, 6) &&
        !memcmp(frame + 10, ap, 6) && !memcmp(frame + 16, ap, 6);
}
inline size_t neighborRequest(uint8_t *out, size_t capacity, uint8_t token,
                              const uint8_t *ssid, size_t ssidLength) {
    if (!out || !token || !ssid || !ssidLength || ssidLength > 32 ||
        capacity < 5 + ssidLength) return 0;
    out[0] = 5; out[1] = 4; out[2] = token;
    out[3] = 0; out[4] = uint8_t(ssidLength);
    memcpy(out + 5, ssid, ssidLength); return 5 + ssidLength;
}
inline size_t btmReject(uint8_t *out, size_t capacity, uint8_t token) {
    if (!out || capacity < 5) return 0;
    out[0] = 10; out[1] = 8; out[2] = token;
    out[3] = 1; out[4] = 0; // Reject unspecified; no target BSSID on rejection.
    return 5;
}
struct Session {
    Capabilities ap;
    Candidates neighbors;
    uint8_t tokenCounter = 0, pendingToken = 0;
    bool requested = false, pending = false, btmReplied = false;
    uint64_t requestMs = 0, neighborsMs = 0, lastBtmMs = 0;
    void reset() {
        const uint8_t previous = tokenCounter;
        *this = {}; tokenCounter = previous; // Do not reuse token 1 every join.
    }
    void expire(uint64_t now) {
        if (pending && (now < requestMs || now - requestMs >= ResponseTimeoutMs))
            pending = false;
        if (neighbors.count && (now < neighborsMs || now - neighborsMs >= CandidateLifetimeMs))
            neighbors = {};
    }
};
enum Stat : unsigned {
    APNeighbor, APBtm, APMobilityDomain, APMdid, APFtPolicy, APFtAkms,
    RequestTx, RequestTxFail, ResponseRx, ResponseInvalid, ResponseTimeout,
    NeighborCount, NeighborTruncated, BtmRx, BtmRejectTx, BtmTxFail,
    BtmInvalid, BtmRateLimited, BtmCandidates, BtmMode, BtmDisassocTimer,
    Count
};
}
