/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
#include <stdint.h>
namespace RTW88IOCTLGuard {
constexpr int DarwinUnsupported=102; // EOPNOTSUPP, independent of Linux compat errno
// Legacy getErrorString is on the supplied stack-canary panic path. These
// optional diagnostics are unsupported; do not enter the family's marshaller
// or guess the size of its stack-local/native/user structures.
inline bool legacyErrorQuery(uint32_t selector) { return selector==209 || selector==210; }
}
