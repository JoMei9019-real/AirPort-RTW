/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

#include <stdint.h>

namespace RTW88LinkNoise {
constexpr int16_t ScanNoiseDbm = -95;
constexpr uint64_t MaxSampleAgeMs = 5000;

enum class Source { Fixed, ThermalEstimate, RxSNR };
struct Reading {
    int16_t dbm;
    Source source;
};

// Thermal model at room temperature with a nominal 6 dB receiver noise figure.
inline int16_t thermalNoiseDbm(uint8_t widthMHz) {
    switch (widthMHz) {
    case 80: return -89;
    case 40: return -92;
    default: return -95;
    }
}

inline uint64_t sample(int rssiDbm, uint8_t snrHalfDb, uint8_t widthMHz, uint64_t nowMs) {
    if (rssiDbm < -110 || rssiDbm >= 0 || snrHalfDb < 2 || snrHalfDb > 100)
        return 0;
    const int noise = rssiDbm - snrHalfDb / 2;
    const int thermal = thermalNoiseDbm(widthMHz);
    if (noise < thermal - 15 || noise > thermal + 15)
        return 0;
    // A single word keeps value, bandwidth and time coherent between RX and IOCTL.
    return (nowMs << 16) | (uint64_t(widthMHz) << 8) | uint64_t(-noise);
}

inline Reading read(bool supported, uint8_t widthMHz, uint64_t cached, uint64_t nowMs) {
    if (!supported)
        return {ScanNoiseDbm, Source::Fixed};
    const uint64_t capturedMs = cached >> 16;
    if (cached && uint8_t(cached >> 8) == widthMHz &&
        nowMs >= capturedMs && nowMs - capturedMs <= MaxSampleAgeMs)
        return {static_cast<int16_t>(-int(uint8_t(cached))), Source::RxSNR};
    return {thermalNoiseDbm(widthMHz), Source::ThermalEstimate};
}
}
