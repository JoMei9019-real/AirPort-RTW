/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * Preserve the pinned rtw88 RX implementation, exposing integrity and SNR.
 * RX_FLAG_DECRYPTED alone does not prove CCMP or a successful MIC check.
 */
#define rtw_rx_query_rx_desc rtw88_original_rx_query_rx_desc
#include "../../rtw88-stable/drivers/net/wireless/realtek/rtw88/rx.c"
#undef rtw_rx_query_rx_desc
#include "rtw88_rx_security.h"

_Static_assert(sizeof(struct ieee80211_rx_status) <= sizeof(((struct sk_buff *)0)->cb),
               "RX status exceeds skb control buffer");

void rtw_rx_query_rx_desc(struct rtw_dev *dev, void *desc,
                         struct rtw_rx_pkt_stat *stat,
                         struct ieee80211_rx_status *status)
{
    status->rtw_snr_half_db = 0;
    rtw88_original_rx_query_rx_desc(dev, desc, stat, status);
    if (stat->is_c2h)
        return;
    const struct rtw_rx_desc *d = desc;
    unsigned cipher = le32_get_bits(d->w0, RTW_RX_DESC_W0_ENC_TYPE);
    _Static_assert(RX_DESC_ENC_AES == 4, "RX CCMP descriptor encoding changed");
    rtw88_rx_security_status(&status->flag, stat->crc_err, stat->icv_err,
                            stat->decrypted, cipher);

    if (dev->chip->id != RTW_CHIP_TYPE_8821C || !stat->phy_status ||
        stat->crc_err || stat->icv_err || status->signal >= 0)
        return;

    /* GET_PHY_STAT_P1_RXSNR_A reads the low byte of PHY-status word 6.
     * Use a byte read because descriptor shift can leave the word unaligned. */
    enum { snr_offset = 6 * sizeof(__le32) };
    if (stat->drv_info_sz <= snr_offset)
        return;
    const u8 *phy = (const u8 *)desc + dev->chip->rx_pkt_desc_sz + stat->shift;
    if ((phy[0] & 0x0f) == 1 && phy[snr_offset] > 0 && phy[snr_offset] <= 100)
        status->rtw_snr_half_db = phy[snr_offset];
}
