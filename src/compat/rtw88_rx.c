/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Preserve the pinned rtw88 RX implementation, exposing its integrity result.
 * RX_FLAG_DECRYPTED alone does not prove CCMP or a successful MIC check.
 */
#define rtw_rx_query_rx_desc rtw88_original_rx_query_rx_desc
#include "../../rtw88-stable/drivers/net/wireless/realtek/rtw88/rx.c"
#undef rtw_rx_query_rx_desc
#include "rtw88_rx_security.h"
void rtw_rx_query_rx_desc(struct rtw_dev *dev, void *desc,
                         struct rtw_rx_pkt_stat *stat,
                         struct ieee80211_rx_status *status)
{
    rtw88_original_rx_query_rx_desc(dev, desc, stat, status);
    const struct rtw_rx_desc *d = desc;
    unsigned cipher = le32_get_bits(d->w0, RTW_RX_DESC_W0_ENC_TYPE);
    _Static_assert(RX_DESC_ENC_AES == 4, "RX CCMP descriptor encoding changed");
    rtw88_rx_security_status(&status->flag, stat->crc_err, stat->icv_err,
                            stat->decrypted, cipher);
}
