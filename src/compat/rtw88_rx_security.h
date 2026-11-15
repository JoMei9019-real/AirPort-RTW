/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
/* Port-private flags: never set from frame contents or DECRYPTED alone. */
#define RX_FLAG_RTW_INTEGRITY_FAILED (1U << 30)
#define RX_FLAG_RTW_CCMP_VERIFIED (1U << 31)
static inline void rtw88_rx_security_status(unsigned *flags, int crc, int icv,
                                           int decrypted, unsigned cipher)
{
    *flags &= ~RX_FLAG_RTW_CCMP_VERIFIED;
    if (crc || icv) {
        *flags |= RX_FLAG_RTW_INTEGRITY_FAILED;
        *flags &= ~RX_FLAG_DECRYPTED;
    } else if (decrypted && cipher == 4) { /* RX_DESC_ENC_AES */
        *flags |= RX_FLAG_RTW_CCMP_VERIFIED;
    }
}
