/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

/* Frame control is in host byte order. QoS Control precedes HT Control. */
static inline int rtw88_is_qos_data(unsigned fc)
{
    return (fc & 0x008c) == 0x0088;
}

static inline unsigned rtw88_qos_offset(unsigned fc)
{
    return (fc & 0x0300) == 0x0300 ? 30 : 24;
}

static inline int rtw88_has_ht_control(unsigned fc)
{
    return rtw88_is_qos_data(fc) && (fc & 0x8000);
}

static inline unsigned rtw88_data_header_length(unsigned fc)
{
    unsigned len = rtw88_qos_offset(fc);
    if (rtw88_is_qos_data(fc))
        len += rtw88_has_ht_control(fc) ? 6 : 2;
    return len;
}
