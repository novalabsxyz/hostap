/*
 * Periodic Wi-Fi statistics collection for hostapd
 * Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This module periodically collects per-station statistics from the driver,
 * keeps them per station in a circular buffer (WINDOW span, the default) or in
 * streaming accumulators (REPORT span), and formats Connect-Info attributes
 * with aggregated metrics per draft-ietf-radext-connectinfo-02.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "radius/radius_client.h"
#include "drivers/driver.h"
#include "hostapd.h"
#include "ap_config.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "wifi_stats.h"
#include "wifi_stats_i.h"

/* Fewer frames are noise: one retry among four EAPOL frames reads 25% */
#define WIFI_STATS_ACC_MIN_FRAMES 20

/* Seconds an instantaneous value may be old, whatever the interval */
#define WIFI_STATS_INSTANT_MAX_AGE 2

/* SAMPLE in AGGR has four digits */
#define WIFI_STATS_MAX_SAMPLE_MS 9999

struct wifi_stats_circular {
	struct wifi_stats_sample *entries;
	size_t max_len;
	size_t head;
	size_t count;
};

struct wifi_stats_link_counters {
	unsigned long rx;
	unsigned long tx;
	unsigned long retry;
	unsigned long failed;
};

struct wifi_stats_sta_buf {
	/*
	 * The station this buffer belongs to, and the only holder of a
	 * pointer to it (sta->wifi_stats). A buffer is freed before its
	 * station and clears that pointer, so neither outlives the other.
	 */
	struct sta_info *sta;
	struct wifi_stats_circular buf;
	struct wifi_stats_accum accum[WIFI_STATS_METRIC_COUNT];
	/*
	 * The latest reading, combined over the links of an MLD station and
	 * not gated by freshness; its timestamp is when it was taken, and
	 * unset before the first one.
	 */
	struct wifi_stats_sample last;
	struct os_reltime period_start;
	/* set by a report, applied by the next sample */
	bool reset_pending;
	struct os_reltime reset_at;
	/* Links (bit = mld_link_id) that reported this period, once each */
	unsigned int signalled_links;
	bool prev_authorized;
	unsigned long prev_rx_packets;
	struct wifi_stats_link_counters prev_link[MAX_NUM_MLD_LINKS];
	/* links in the previous sample */
	unsigned int prev_link_mask;
	/* a sample was taken in the current collection */
	bool sampled;
	struct wifi_stats_sta_buf *next;
};

struct wifi_stats_ctx {
	unsigned int collection_interval;
	unsigned int window_seconds;
	unsigned int ewma_weight;
	enum wifi_stats_span_mode span_mode;
	struct hostapd_iface *iface;
	int timer_active;
	enum wifi_stats_agg_type agg_config[WIFI_STATS_METRIC_COUNT];
	struct wifi_stats_sta_buf *sta_bufs;
};


static int wifi_stats_circular_init(struct wifi_stats_circular *buf,
				    size_t max_len)
{
	buf->max_len = max_len;
	buf->head = 0;
	buf->count = 0;

	if (max_len == 0) {
		buf->entries = NULL;
		return 0;
	}

	buf->entries = os_calloc(max_len, sizeof(*buf->entries));
	if (!buf->entries) {
		buf->max_len = 0;
		return -1;
	}

	return 0;
}


static void wifi_stats_circular_free(struct wifi_stats_circular *buf)
{
	os_free(buf->entries);
	buf->entries = NULL;
}


static void wifi_stats_circular_push(struct wifi_stats_circular *buf,
				     const struct wifi_stats_sample *entry)
{
	buf->entries[buf->head] = *entry;
	buf->head = (buf->head + 1) % buf->max_len;
	if (buf->count < buf->max_len)
		buf->count++;
}


static int wifi_stats_all_metrics_none(struct wifi_stats_ctx *ctx)
{
	int i;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (ctx->agg_config[i] != WIFI_STATS_AGG_NONE)
			return 0;
	}
	return 1;
}


static size_t wifi_stats_compute_buf_max(struct wifi_stats_ctx *ctx)
{
	if (ctx->span_mode == WIFI_STATS_SPAN_REPORT)
		return 0;
	return ctx->window_seconds / ctx->collection_interval + 1;
}


static struct wifi_stats_sta_buf * wifi_stats_sta_buf_alloc(
	struct wifi_stats_ctx *ctx, struct sta_info *sta)
{
	struct wifi_stats_sta_buf *sb;
	size_t max_len;

	max_len = wifi_stats_compute_buf_max(ctx);

	sb = os_zalloc(sizeof(*sb));
	if (!sb)
		return NULL;

	sb->sta = sta;
	if (wifi_stats_circular_init(&sb->buf, max_len) < 0) {
		os_free(sb);
		return NULL;
	}

	sb->next = ctx->sta_bufs;
	ctx->sta_bufs = sb;
	sta->wifi_stats = sb;

	wpa_printf(MSG_DEBUG, "wifi_stats: Allocated buffer for " MACSTR
		   " (max_len=%zu)", MAC2STR(sta->addr), max_len);

	return sb;
}


/* The buffer must already be off the context's list */
static void wifi_stats_release_buf(struct wifi_stats_sta_buf *sb)
{
	sb->sta->wifi_stats = NULL;
	wifi_stats_circular_free(&sb->buf);
	os_free(sb);
}


static void wifi_stats_remove_buf(struct wifi_stats_ctx *ctx,
				  struct wifi_stats_sta_buf *sb)
{
	struct wifi_stats_sta_buf **pp;

	for (pp = &ctx->sta_bufs; *pp != sb; pp = &(*pp)->next)
		;
	*pp = sb->next;
	wifi_stats_release_buf(sb);
}


/* Nothing collected survives; the next collection starts every station anew */
static void wifi_stats_free_all_bufs(struct wifi_stats_ctx *ctx)
{
	struct wifi_stats_sta_buf *sb;

	while ((sb = ctx->sta_bufs)) {
		ctx->sta_bufs = sb->next;
		wifi_stats_release_buf(sb);
	}
}


/* Algorithm defaults per draft-ietf-radext-connectinfo-02 Section 4.2 */
static enum wifi_stats_agg_type
wifi_stats_default_algorithm(enum wifi_stats_metric_type metric)
{
	switch (metric) {
	case WIFI_STATS_METRIC_RX_BITRATE:
	case WIFI_STATS_METRIC_TX_BITRATE:
		return WIFI_STATS_AGG_MAX;
	case WIFI_STATS_METRIC_RSSI:
		return WIFI_STATS_AGG_AVG_LIN;
	case WIFI_STATS_METRIC_FRAME_LOSS:
	case WIFI_STATS_METRIC_FRAME_RETRY:
		return WIFI_STATS_AGG_ACC;
	case WIFI_STATS_METRIC_COUNT:
		break;
	}
	return WIFI_STATS_AGG_COUNT;
}


static const char *metric_names[WIFI_STATS_METRIC_COUNT] = {
	[WIFI_STATS_METRIC_RX_BITRATE] = "RxBitRate",
	[WIFI_STATS_METRIC_TX_BITRATE] = "TxBitRate",
	[WIFI_STATS_METRIC_RSSI] = "RSSI",
	[WIFI_STATS_METRIC_FRAME_LOSS] = "FrameLoss",
	[WIFI_STATS_METRIC_FRAME_RETRY] = "FrameRetry"
};

static const char *span_mode_strings[WIFI_STATS_SPAN_COUNT] = {
	[WIFI_STATS_SPAN_REPORT] = "report",
	[WIFI_STATS_SPAN_WINDOW] = "window"
};

static const char *agg_type_strings[WIFI_STATS_AGG_COUNT] = {
	[WIFI_STATS_AGG_MIN] = "MIN",
	[WIFI_STATS_AGG_MAX] = "MAX",
	[WIFI_STATS_AGG_AVG_LIN] = "AVG-LIN",
	[WIFI_STATS_AGG_AVG_EXP] = "AVG-EXP",
	[WIFI_STATS_AGG_ACC] = "ACC",
	[WIFI_STATS_AGG_NONE] = "NONE"
};


/*
 * The span from the first to the last timestamp as WINDOW. With max_seconds
 * set, what is written never reads longer than that many seconds.
 */
void wifi_stats_timeframe_str(char *buffer, size_t buffer_len,
			      const struct os_reltime *timestamps,
			      int point_count, unsigned int max_seconds)
{
	long sec_diff;
	int usec_diff;
	int total_seconds;
	int minutes;

	if (point_count < 2) {
		os_snprintf(buffer, buffer_len, "1S");
		return;
	}

	/* Span rounded to the nearest second */
	sec_diff = timestamps[point_count - 1].sec - timestamps[0].sec;
	usec_diff = timestamps[point_count - 1].usec - timestamps[0].usec;
	if (usec_diff < 0) {
		sec_diff--;
		usec_diff += 1000000;
	}
	total_seconds = (int) sec_diff + (usec_diff >= 500000 ? 1 : 0);

	if (max_seconds && total_seconds > (int) max_seconds)
		total_seconds = max_seconds;
	if (total_seconds < 1)
		total_seconds = 1;

	/* Spec ABNF limits WINDOW to 3 digits; switch to minutes above 999s */
	if (total_seconds <= 999) {
		os_snprintf(buffer, buffer_len, "%dS", total_seconds);
	} else {
		minutes = (total_seconds + 30) / 60;
		/* rounded up, the minutes would read longer than the bound */
		if (max_seconds && minutes * 60 > (int) max_seconds)
			minutes = max_seconds / 60;
		if (minutes > 999)
			minutes = 999;
		os_snprintf(buffer, buffer_len, "%dM", minutes);
	}
}


/*
 * Signal and rates are 0 when the driver has no last frame; a counter can
 * legitimately read 0.
 */
static bool wifi_stats_skip_zero(enum wifi_stats_metric_type metric,
				 double value)
{
	if (value != 0.0)
		return false;
	return metric == WIFI_STATS_METRIC_RSSI ||
		metric == WIFI_STATS_METRIC_TX_BITRATE ||
		metric == WIFI_STATS_METRIC_RX_BITRATE;
}


static void wifi_stats_sample_set(struct wifi_stats_sample *sample,
				  const struct hostap_sta_driver_data *data,
				  const struct os_reltime *timestamp)
{
	sample->timestamp = *timestamp;
	sample->tx_packets = data->tx_packets;
	sample->tx_retry_count = data->tx_retry_count;
	sample->tx_retry_failed = data->tx_retry_failed;
	sample->current_tx_rate = data->current_tx_rate;
	sample->current_rx_rate = data->current_rx_rate;
	sample->signal = data->signal;
}


static double extract_station_metric(const struct wifi_stats_sample *sample,
				     enum wifi_stats_metric_type metric)
{
	switch (metric) {
	case WIFI_STATS_METRIC_RX_BITRATE:
		return (double) sample->current_rx_rate;
	case WIFI_STATS_METRIC_TX_BITRATE:
		return (double) sample->current_tx_rate;
	case WIFI_STATS_METRIC_RSSI:
		return (double) sample->signal;
	case WIFI_STATS_METRIC_FRAME_RETRY:
		return (double) sample->tx_retry_count;
	case WIFI_STATS_METRIC_FRAME_LOSS:
		return (double) sample->tx_retry_failed;
	case WIFI_STATS_METRIC_COUNT:
		break;
	}
	return 0.0;
}


/*
 * Per draft-ietf-radext-connectinfo-02 Section 2 the maximum rate, amendment
 * and channel are "not uniquely associated with a single IEEE 802.11
 * connection": they describe the BSS, not the station.
 */
enum wifi_stats_amendment {
	WIFI_STATS_AMD_B,
	WIFI_STATS_AMD_G,
	WIFI_STATS_AMD_A,
	WIFI_STATS_AMD_N,
	WIFI_STATS_AMD_AC,
	WIFI_STATS_AMD_AX,
	WIFI_STATS_AMD_BE,
	WIFI_STATS_AMD_BN,
};

/* The draft's b/g/a/n/ac/ax/be list is read as open, so bn is reported */
static const char *wifi_stats_amendment_str[] = {
	[WIFI_STATS_AMD_B] = "b",
	[WIFI_STATS_AMD_G] = "g",
	[WIFI_STATS_AMD_A] = "a",
	[WIFI_STATS_AMD_N] = "n",
	[WIFI_STATS_AMD_AC] = "ac",
	[WIFI_STATS_AMD_AX] = "ax",
	[WIFI_STATS_AMD_BE] = "be",
	[WIFI_STATS_AMD_BN] = "bn",
};


static enum wifi_stats_amendment
wifi_stats_bss_amendment(struct hostapd_data *hapd)
{
	struct hostapd_config *conf = hapd->iconf;
	struct hostapd_bss_config *bss = hapd->conf;

	if (conf->ieee80211bn && !bss->disable_11bn)
		return WIFI_STATS_AMD_BN;
	if (conf->ieee80211be && !bss->disable_11be)
		return WIFI_STATS_AMD_BE;
	if (conf->ieee80211ax && !bss->disable_11ax)
		return WIFI_STATS_AMD_AX;
	if (conf->ieee80211ac && !bss->disable_11ac)
		return WIFI_STATS_AMD_AC;
	if (conf->ieee80211n && !bss->disable_11n)
		return WIFI_STATS_AMD_N;
	if (conf->hw_mode == HOSTAPD_MODE_IEEE80211B)
		return WIFI_STATS_AMD_B;
	if (conf->hw_mode == HOSTAPD_MODE_IEEE80211G)
		return WIFI_STATS_AMD_G;
	return WIFI_STATS_AMD_A;
}


/* Operating width in MHz of the given amendment's PHY in this BSS */
static int wifi_stats_get_channel_width(struct hostapd_config *conf,
					enum wifi_stats_amendment amd)
{
	int chw = CONF_OPER_CHWIDTH_USE_HT;

	switch (amd) {
	case WIFI_STATS_AMD_BN:
	case WIFI_STATS_AMD_BE:
#ifdef CONFIG_IEEE80211BE
		chw = conf->eht_oper_chwidth;
#endif /* CONFIG_IEEE80211BE */
		break;
	case WIFI_STATS_AMD_AX:
#ifdef CONFIG_IEEE80211AX
		chw = conf->he_oper_chwidth;
#endif /* CONFIG_IEEE80211AX */
		break;
	case WIFI_STATS_AMD_AC:
		chw = conf->vht_oper_chwidth;
		break;
	case WIFI_STATS_AMD_N:
		return conf->secondary_channel ? 40 : 20;
	default:
		return 20;
	}

	switch (chw) {
	case CONF_OPER_CHWIDTH_320MHZ:
		return 320;
	case CONF_OPER_CHWIDTH_160MHZ:
	case CONF_OPER_CHWIDTH_80P80MHZ:
		return 160;
	case CONF_OPER_CHWIDTH_80MHZ:
		return 80;
	case CONF_OPER_CHWIDTH_40MHZ_6GHZ:
		return 40;
	default:
		return conf->secondary_channel ? 40 : 20;
	}
}


/*
 * Transmit streams from the HT Supported MCS Set: the Rx mask is bytes 0-9
 * and the Tx parameters octet is byte 12. Tx Maximum Number of Spatial
 * Streams (bits 2-3) is valid only when the Tx set is defined (bit 0) and
 * differs from the Rx set (bit 1); otherwise Tx matches the Rx mask.
 */
static int wifi_stats_nss_from_ht_mcs_set(const u8 *mcs_set)
{
	int i, nss = 0;

	if ((mcs_set[12] & 0x03) == 0x03)
		return ((mcs_set[12] >> 2) & 0x03) + 1;

	for (i = 0; i < 4; i++) {
		if (mcs_set[i])
			nss = i + 1;
	}

	return nss;
}


/*
 * Data rate in Mbps per the MAXSPEED formula of the draft,
 * SC * MD * CR * SS / (SYM + GD), with the coding rate as cr_num/cr_den.
 */
static double wifi_stats_phy_rate(int sc, int md, int cr_num, int cr_den,
				  int nss, double sym_us, double gi_us)
{
	return (double) sc * md * cr_num * nss / cr_den / (sym_us + gi_us);
}


/* Data subcarriers by width index 20/40/80/160/320 MHz */
static int wifi_stats_subcarriers(enum wifi_stats_amendment amd, int width)
{
	static const int ht_vht[] = { 52, 108, 234, 468, 0 };
	static const int he_eht[] = { 234, 468, 980, 1960, 3920 };
	int idx;

	switch (width) {
	case 320:
		idx = 4;
		break;
	case 160:
		idx = 3;
		break;
	case 80:
		idx = 2;
		break;
	case 40:
		idx = 1;
		break;
	default:
		idx = 0;
		break;
	}

	if (amd >= WIFI_STATS_AMD_AX)
		return he_eht[idx];
	return ht_vht[idx];
}


/*
 * VHT MCS 9 is not a valid combination at 20 MHz except for 3 and 6 streams,
 * at 80 MHz for 6 streams and at 160 MHz for 3 streams (the VHT-MCS tables
 * of IEEE Std 802.11-2020, 21.5); the top rate there is MCS 8.
 */
static bool wifi_stats_vht_mcs9_valid(int width, int nss)
{
	if (width == 20)
		return nss == 3 || nss == 6;
	if (width == 80)
		return nss != 6;
	if (width == 160)
		return nss != 3;
	return true;
}


/* VHT and HE Tx MCS maps hold two bits per stream, 3 meaning unsupported */
static int wifi_stats_mcs_map_code(u16 map, int nss)
{
	return (map >> ((nss - 1) * 2)) & 0x3;
}


static double wifi_stats_vht_rate(int sc, int width, int nss, int code)
{
	/* codes 0, 1, 2 are MCS 0-7, 0-8, 0-9 */
	if (code == 2 && wifi_stats_vht_mcs9_valid(width, nss))
		return wifi_stats_phy_rate(sc, 8, 5, 6, nss, 3.2, 0.4);
	if (code >= 1)
		return wifi_stats_phy_rate(sc, 8, 3, 4, nss, 3.2, 0.4);
	return wifi_stats_phy_rate(sc, 6, 5, 6, nss, 3.2, 0.4);
}


static double wifi_stats_he_rate(int sc, int nss, int code)
{
	/* codes 0, 1, 2 are MCS 0-7, 0-9, 0-11 */
	static const int md[] = { 6, 8, 10 };

	return wifi_stats_phy_rate(sc, md[code], 5, 6, nss, 12.8, 0.8);
}


static double wifi_stats_ht_maxspeed(struct hostapd_hw_modes *mode, int width)
{
	int nss = mode ? wifi_stats_nss_from_ht_mcs_set(mode->mcs_set) : 0;

	/* MCS 7 per stream at the 400 ns short guard interval */
	return wifi_stats_phy_rate(wifi_stats_subcarriers(WIFI_STATS_AMD_N,
							  width),
				   6, 5, 6, nss > 0 ? nss : 1, 3.2, 0.4);
}


/*
 * The mode whose VHT capabilities hostapd advertises: a 2.4 GHz BSS with
 * vendor_vht and no VHT capabilities of its own borrows the 5 GHz band's,
 * as mode_for_vht_capab() in ieee802_11_vht.c does.
 */
static struct hostapd_hw_modes *
wifi_stats_vht_caps_mode(struct hostapd_data *hapd,
			 struct hostapd_hw_modes *mode)
{
	int i;

	if (!mode || mode->mode != HOSTAPD_MODE_IEEE80211G ||
	    !hapd->conf->vendor_vht || mode->vht_capab ||
	    !hapd->iface->hw_features)
		return mode;

	for (i = 0; i < hapd->iface->num_hw_features; i++) {
		if (hapd->iface->hw_features[i].mode == HOSTAPD_MODE_IEEE80211A)
			return &hapd->iface->hw_features[i];
	}
	return mode;
}


static double wifi_stats_vht_maxspeed(struct hostapd_data *hapd,
				      struct hostapd_hw_modes *mode,
				      int width)
{
	int sc = wifi_stats_subcarriers(WIFI_STATS_AMD_AC, width);
	double best = 0.0, rate;
	int nss, code;

	mode = wifi_stats_vht_caps_mode(hapd, mode);
	/* a mode without VHT capabilities has an all-zero, meaningless map */
	if (mode && mode->vht_capab) {
		u16 map = WPA_GET_LE16(&mode->vht_mcs_set[4]);

		for (nss = 1; nss <= 8; nss++) {
			code = wifi_stats_mcs_map_code(map, nss);
			if (code == 3)
				continue;
			rate = wifi_stats_vht_rate(sc, width, nss, code);
			if (rate > best)
				best = rate;
		}
	}
	return best > 0.0 ? best : wifi_stats_vht_rate(sc, width, 1, 2);
}


static double wifi_stats_he_maxspeed(struct hostapd_data *hapd,
				     struct hostapd_hw_modes *mode, int width)
{
	int sc = wifi_stats_subcarriers(WIFI_STATS_AMD_AX, width);
	double best = 0.0, rate;
	int nss, code;

	if (mode && mode->he_capab[IEEE80211_MODE_AP].he_supported) {
		const struct he_capabilities *he =
			&mode->he_capab[IEEE80211_MODE_AP];
		int offset = 2;
		u16 map;

		/*
		 * Tx maps follow the Rx ones: <= 80 MHz at 2, 160 MHz at 6,
		 * 80+80 MHz at 10.
		 */
#ifdef CONFIG_IEEE80211AX
		if (hapd->iconf->he_oper_chwidth == CONF_OPER_CHWIDTH_80P80MHZ)
			offset = 10;
		else
#endif /* CONFIG_IEEE80211AX */
		if (width >= 160)
			offset = 6;
		map = WPA_GET_LE16(&he->mcs[offset]);
		for (nss = 1; nss <= 8; nss++) {
			code = wifi_stats_mcs_map_code(map, nss);
			if (code == 3)
				continue;
			rate = wifi_stats_he_rate(sc, nss, code);
			if (rate > best)
				best = rate;
		}
	}
	return best > 0.0 ? best : wifi_stats_he_rate(sc, 1, 2);
}


static double wifi_stats_eht_maxspeed(struct hostapd_hw_modes *mode,
				      int width)
{
	/* top MCS of each EHT-MCS map octet: 9, 11 and 13 */
	static const int md[] = { 8, 10, 12 };
	int sc = wifi_stats_subcarriers(WIFI_STATS_AMD_BE, width);
	double best = 0.0, rate;
	int bw, tier, nss;

	if (mode && mode->eht_capab[IEEE80211_MODE_AP].eht_supported) {
		const struct eht_capabilities *eht =
			&mode->eht_capab[IEEE80211_MODE_AP];

		/*
		 * One three-octet EHT-MCS map per bandwidth (<= 80, 160, 320
		 * MHz), each octet giving the Tx NSS in its high nibble for
		 * MCS 0-9, 10-11, 12-13.
		 */
		bw = width >= 320 ? 2 : width >= 160 ? 1 : 0;
		for (tier = 0; tier < 3; tier++) {
			nss = eht->mcs[3 * bw + tier] >> 4;
			if (!nss)
				continue;
			rate = wifi_stats_phy_rate(sc, md[tier], 5, 6, nss,
						   12.8, 0.8);
			if (rate > best)
				best = rate;
		}
	}
	return best > 0.0 ? best : wifi_stats_phy_rate(sc, 12, 5, 6, 1, 12.8,
						       0.8);
}


/*
 * MAXSPEED per the draft: "a network-level capability indicator, not the
 * negotiated or currently achieved rate of a station", with the amendment's
 * shortest guard interval and the SS, MD and CR this AP advertises, else one
 * stream at the amendment's top MCS.
 */
double wifi_stats_bss_maxspeed(struct hostapd_data *hapd)
{
	enum wifi_stats_amendment amd = wifi_stats_bss_amendment(hapd);
	struct hostapd_hw_modes *mode = hapd->iface ?
		hapd->iface->current_mode : NULL;
	int width = wifi_stats_get_channel_width(hapd->iconf, amd);

	switch (amd) {
	case WIFI_STATS_AMD_BN:
	case WIFI_STATS_AMD_BE:
		return wifi_stats_eht_maxspeed(mode, width);
	case WIFI_STATS_AMD_AX:
		return wifi_stats_he_maxspeed(hapd, mode, width);
	case WIFI_STATS_AMD_AC:
		return wifi_stats_vht_maxspeed(hapd, mode, width);
	case WIFI_STATS_AMD_N:
		return wifi_stats_ht_maxspeed(mode, width);
	case WIFI_STATS_AMD_B:
		/* DSSS/CCK is not OFDM; the formula does not apply */
		return 11.0;
	default:
		return wifi_stats_phy_rate(48, 6, 3, 4, 1, 3.2, 0.8);
	}
}


/*
 * Reset semantics differ per algorithm. MIN/MAX/AVG-LIN discard their state.
 * ACC must carry the current counter pair forward as the new baseline.
 * AVG-EXP keeps its filter state entirely.
 */
static void wifi_stats_accum_reset(struct wifi_stats_accum *acc)
{
	double ewma = acc->ewma;
	int ewma_valid = acc->ewma_valid;
	double last_val = acc->last_val;
	double last_base = acc->last_base;
	struct os_reltime last_ts = acc->last_ts;

	os_memset(acc, 0, sizeof(*acc));

	acc->ewma = ewma;
	acc->ewma_valid = ewma_valid;
	acc->first_val = last_val;
	acc->first_base = last_base;
	acc->last_val = last_val;
	acc->last_base = last_base;
	acc->first_ts = last_ts;
	acc->last_ts = last_ts;
	acc->base_ts = last_ts;
}


static void wifi_stats_accum_reset_all(struct wifi_stats_sta_buf *sb,
				       const struct os_reltime *now)
{
	int metric;

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++)
		wifi_stats_accum_reset(&sb->accum[metric]);
	sb->period_start = *now;
}


void wifi_stats_accum_update(struct wifi_stats_accum *acc, double value,
			     double base, const struct os_reltime *now,
			     unsigned int ewma_weight)
{
	double alpha;

	if (acc->count == 0) {
		acc->min = value;
		acc->max = value;
		acc->sum = value;
		acc->first_ts = *now;
		if (!os_reltime_initialized(&acc->last_ts)) {
			acc->first_val = value;
			acc->first_base = base;
			acc->base_ts = *now;
		}
	} else {
		if (value < acc->min)
			acc->min = value;
		if (value > acc->max)
			acc->max = value;
		acc->sum += value;
	}

	if (!acc->ewma_valid) {
		acc->ewma = value;
		acc->ewma_valid = 1;
	} else {
		alpha = 1.0 / (double) (1U << ewma_weight);
		acc->ewma += alpha * (value - acc->ewma);
	}

	if ((acc->count > 0 || os_reltime_initialized(&acc->last_ts)) &&
	    (value < acc->last_val || base < acc->last_base)) {
		acc->first_val = value;
		acc->first_base = base;
		acc->base_ts = *now;
	}

	acc->last_val = value;
	acc->last_base = base;
	acc->last_ts = *now;
	acc->count++;
}


/*
 * AVG-EXP steps once per collection interval. An interval with no fresh value
 * steps toward the last fresh one again; count and AGGR see fresh values only.
 */
void wifi_stats_accum_hold(struct wifi_stats_accum *acc,
			   unsigned int ewma_weight)
{
	double alpha;

	if (!acc->count)
		return;
	alpha = 1.0 / (double) (1U << ewma_weight);
	acc->ewma += alpha * (acc->last_val - acc->ewma);
}


static double wifi_stats_metric_base(const struct wifi_stats_sample *sample,
				     enum wifi_stats_metric_type metric)
{
	switch (metric) {
	case WIFI_STATS_METRIC_FRAME_LOSS:
		return (double) sample->tx_packets;
	case WIFI_STATS_METRIC_FRAME_RETRY:
		return (double) (sample->tx_packets + sample->tx_retry_count);
	case WIFI_STATS_METRIC_RX_BITRATE:
	case WIFI_STATS_METRIC_TX_BITRATE:
	case WIFI_STATS_METRIC_RSSI:
	case WIFI_STATS_METRIC_COUNT:
		break;
	}
	return 0.0;
}


/*
 * Longest REPORT period without a report, 0 for no bound. With accounting,
 * twice the interim interval tolerates one late report, and without interim
 * reports the next is the Stop. Without accounting the window bounds it.
 */
static unsigned int wifi_stats_report_bound(struct wifi_stats_ctx *ctx,
					    struct hostapd_data *hapd,
					    const struct sta_info *sta)
{
	unsigned int interim;

	if (!hapd->conf->radius || !hapd->conf->radius->acct_server)
		return ctx->window_seconds;
	if (sta->acct_interim_interval <= 0)
		return 0;
	interim = 2 * (unsigned int) sta->acct_interim_interval;
	return interim > ctx->window_seconds ? interim : ctx->window_seconds;
}


static unsigned int wifi_stats_link_bit(const struct hostapd_data *hapd)
{
#ifdef CONFIG_IEEE80211BE
	return BIT(hapd->mld_link_id);
#else /* CONFIG_IEEE80211BE */
	return 1;
#endif /* CONFIG_IEEE80211BE */
}


static void wifi_stats_accum_collect(struct wifi_stats_ctx *ctx,
				     struct wifi_stats_sta_buf *sb,
				     const struct wifi_stats_sample *sample,
				     const struct os_reltime *now,
				     unsigned int bound)
{
	int metric;

	sb->signalled_links = 0;
	if (sb->reset_pending) {
		wifi_stats_accum_reset_all(sb, &sb->reset_at);
		sb->reset_pending = false;
	}

	if (os_reltime_initialized(&sb->period_start) && bound &&
	    now->sec - sb->period_start.sec > (long) bound)
		wifi_stats_accum_reset_all(sb, now);
	else if (!os_reltime_initialized(&sb->period_start))
		sb->period_start = *now;

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
		double value = extract_station_metric(sample, metric);

		if (wifi_stats_skip_zero(metric, value)) {
			wifi_stats_accum_hold(&sb->accum[metric],
					      ctx->ewma_weight);
			continue;
		}
		wifi_stats_accum_update(&sb->accum[metric], value,
					wifi_stats_metric_base(sample, metric),
					now, ctx->ewma_weight);
	}
}


double wifi_stats_accum_value(const struct wifi_stats_accum *acc,
			      enum wifi_stats_agg_type algorithm)
{
	double base_delta;

	switch (algorithm) {
	case WIFI_STATS_AGG_MIN:
		return acc->min;
	case WIFI_STATS_AGG_MAX:
		return acc->max;
	case WIFI_STATS_AGG_AVG_LIN:
		return acc->count ? acc->sum / acc->count : 0.0;
	case WIFI_STATS_AGG_AVG_EXP:
		return acc->ewma;
	case WIFI_STATS_AGG_ACC:
		base_delta = acc->last_base - acc->first_base;
		if (base_delta <= 0.0)
			return 0.0;
		return ((acc->last_val - acc->first_val) / base_delta) * 100.0;
	case WIFI_STATS_AGG_NONE:
	case WIFI_STATS_AGG_COUNT:
		break;
	}
	return 0.0;
}


static void wifi_stats_log_result(const struct wifi_stats_sta_buf *sta_buf,
				  enum wifi_stats_metric_type metric,
				  const struct wifi_stats_agg_result *result)
{
	if (result->actual_points <= 0)
		return;
	wpa_printf(MSG_DEBUG,
		   "wifi_stats: " MACSTR " %s: %.1f (%s %s, %d points)",
		   MAC2STR(sta_buf->sta->addr),
		   metric_names[metric], result->value,
		   wifi_stats_agg_type_to_str(result->algorithm),
		   result->timeframe_str, result->actual_points);
}


/*
 * The result of one metric from its accumulator, for both spans. span_start
 * is where the reported span begins for everything but ACC, which begins at
 * its baseline sample; a nonzero max_seconds bounds the span written.
 */
static void wifi_stats_accum_result(const struct wifi_stats_accum *acc,
				    enum wifi_stats_agg_type config,
				    const struct os_reltime *span_start,
				    unsigned int max_seconds,
				    struct wifi_stats_agg_result *result)
{
	struct os_reltime span[2];
	int is_acc = config == WIFI_STATS_AGG_ACC;
	int rebased = is_acc &&
		(acc->base_ts.sec != acc->first_ts.sec ||
		 acc->base_ts.usec != acc->first_ts.usec);

	result->algorithm = config;

	if (config == WIFI_STATS_AGG_NONE)
		return;

	result->actual_points = (int) acc->count + (rebased ? 1 : 0);
	result->value = wifi_stats_accum_value(acc, config);
	result->base_delta = acc->last_base - acc->first_base;

	span[0] = is_acc ? acc->base_ts : *span_start;
	span[1] = acc->last_ts;
	wifi_stats_timeframe_str(result->timeframe_str,
				 sizeof(result->timeframe_str), span,
				 result->actual_points > 1 ? 2 : 0,
				 max_seconds);
}


/*
 * Section 4.2: "since the last time the connect-info was signaled". The
 * span starts at the report, not at the first sample after it.
 */
static void wifi_stats_aggregate_accum(
	struct wifi_stats_ctx *ctx, struct wifi_stats_sta_buf *sta_buf,
	struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT])
{
	int metric;

	os_memset(results, 0,
		  sizeof(struct wifi_stats_agg_result) *
		  WIFI_STATS_METRIC_COUNT);

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
		wifi_stats_accum_result(&sta_buf->accum[metric],
					ctx->agg_config[metric],
					&sta_buf->period_start, 0,
					&results[metric]);
		wifi_stats_log_result(sta_buf, metric, &results[metric]);
	}
}


/*
 * The samples within the window, oldest first, are folded into accumulators
 * of their own, so a window and a report aggregate with the same code. A
 * sample is admitted when its age in whole seconds is within the window; the
 * timer drifts, so the admitted samples can cover up to a second more than
 * the window, which the reported span is bounded by.
 */
static void wifi_stats_aggregate_window(
	struct wifi_stats_ctx *ctx, struct wifi_stats_sta_buf *sta_buf,
	struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT])
{
	struct wifi_stats_accum accum[WIFI_STATS_METRIC_COUNT];
	struct os_reltime now;
	size_t i;
	int metric;

	os_memset(results, 0,
		  sizeof(struct wifi_stats_agg_result) *
		  WIFI_STATS_METRIC_COUNT);

	os_get_reltime(&now);
	os_memset(accum, 0, sizeof(accum));

	for (i = 0; i < sta_buf->buf.count; i++) {
		size_t idx = (sta_buf->buf.head - sta_buf->buf.count + i +
			      sta_buf->buf.max_len) % sta_buf->buf.max_len;
		const struct wifi_stats_sample *entry =
			&sta_buf->buf.entries[idx];
		long age_sec;

		age_sec = now.sec - entry->timestamp.sec;
		if (age_sec < 0)
			age_sec = 0;
		if ((unsigned int) age_sec > ctx->window_seconds)
			continue;

		for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
			double value = extract_station_metric(entry, metric);

			if (ctx->agg_config[metric] == WIFI_STATS_AGG_NONE ||
			    wifi_stats_skip_zero(metric, value))
				continue;
			wifi_stats_accum_update(&accum[metric], value,
						wifi_stats_metric_base(entry,
								       metric),
						&entry->timestamp,
						ctx->ewma_weight);
		}
	}

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
		struct wifi_stats_agg_result *result = &results[metric];

		wifi_stats_accum_result(&accum[metric], ctx->agg_config[metric],
					&accum[metric].first_ts,
					ctx->window_seconds, result);
		/* the running filter, not seeded by the window */
		if (result->algorithm == WIFI_STATS_AGG_AVG_EXP)
			result->value = result->actual_points > 0 ?
				sta_buf->accum[metric].ewma : 0.0;
		wifi_stats_log_result(sta_buf, metric, result);
	}
}


static void wifi_stats_aggregate_for_station(
	struct wifi_stats_ctx *ctx, struct wifi_stats_sta_buf *sta_buf,
	struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT])
{
	if (ctx->span_mode == WIFI_STATS_SPAN_REPORT)
		wifi_stats_aggregate_accum(ctx, sta_buf, results);
	else
		wifi_stats_aggregate_window(ctx, sta_buf, results);
}


static void wifi_stats_timer_cb(void *eloop_ctx, void *timeout_ctx);

static void wifi_stats_stop_timer(struct wifi_stats_ctx *ctx)
{
	if (ctx->timer_active) {
		wpa_printf(MSG_DEBUG, "wifi_stats: Stopping collection timer");
		eloop_cancel_timeout(wifi_stats_timer_cb, ctx, NULL);
		ctx->timer_active = 0;
	}
}


static struct wifi_stats_ctx * wifi_stats_ctx_new(struct hostapd_iface *iface)
{
	struct wifi_stats_ctx *ctx;
	int i;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->iface = iface;
	ctx->collection_interval = WIFI_STATS_DEFAULT_INTERVAL;
	ctx->window_seconds = WIFI_STATS_DEFAULT_WINDOW;
	ctx->ewma_weight = WIFI_STATS_DEFAULT_EWMA_WEIGHT;
	ctx->span_mode = WIFI_STATS_SPAN_WINDOW;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
		ctx->agg_config[i] = wifi_stats_default_algorithm(i);

	return ctx;
}


#ifdef CONFIG_IEEE80211BE
/*
 * An MLD station is collected on its association link: for the sta_info of
 * another link, return the association link's BSS and sta_info, else NULL.
 */
static struct hostapd_data *
wifi_stats_mld_assoc_link(struct hostapd_data *hapd, struct sta_info *sta,
			  struct sta_info **assoc_sta)
{
	struct hostapd_data *assoc;

	if (!ap_sta_is_mld(hapd, sta) ||
	    sta->mld_assoc_link_id == hapd->mld_link_id)
		return NULL;
	assoc = hostapd_mld_get_link_bss(hapd, sta->mld_assoc_link_id);
	*assoc_sta = assoc ? ap_get_sta(assoc, sta->addr) : NULL;
	return *assoc_sta ? assoc : NULL;
}
#endif /* CONFIG_IEEE80211BE */


/*
 * Links report in any order, each at most once per period. Only the
 * association link, or a non-MLD station, schedules the reset for the next
 * sample; a partner link only sets its own bit.
 */
void wifi_stats_mark_signalled(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct wifi_stats_ctx *ctx;
	struct wifi_stats_sta_buf *sb = NULL;
	bool partner = false;
	struct os_reltime now;

	if (!hapd->iface->wifi_stats)
		return;
	ctx = hapd->iface->wifi_stats;
	sb = sta->wifi_stats;

#ifdef CONFIG_IEEE80211BE
	{
		struct hostapd_data *assoc;
		struct sta_info *assoc_sta;

		/*
		 * By role, not by whose buffer is used: after ML
		 * reconfiguration moved the association link, the old one's
		 * Accounting-Stop is a partner's report.
		 */
		partner = ap_sta_is_mld(hapd, sta) &&
			sta->mld_assoc_link_id != hapd->mld_link_id;
		assoc = wifi_stats_mld_assoc_link(hapd, sta, &assoc_sta);
		if (assoc && assoc->iface->wifi_stats &&
		    assoc_sta->wifi_stats) {
			sb = assoc_sta->wifi_stats;
			ctx = assoc->iface->wifi_stats;
		}
	}
#endif /* CONFIG_IEEE80211BE */
	if (!sb || ctx->span_mode != WIFI_STATS_SPAN_REPORT)
		return;

	sb->signalled_links |= wifi_stats_link_bit(hapd);
	if (partner)
		return;
	os_get_reltime(&now);
	sb->reset_pending = true;
	sb->reset_at = now;
	wpa_printf(MSG_DEBUG, "wifi_stats: Reset aggregation for " MACSTR
		   " after accounting report", MAC2STR(sb->sta->addr));
}


static void wifi_stats_forget_sta(struct wifi_stats_ctx *ctx,
				  struct sta_info *sta)
{
	if (!sta->wifi_stats)
		return;
	wpa_printf(MSG_DEBUG, "wifi_stats: Forgot buffer for " MACSTR,
		   MAC2STR(sta->addr));
	wifi_stats_remove_buf(ctx, sta->wifi_stats);
}


/* Driver counters restart at 0 on each (re)association, even on one sta_info */
void wifi_stats_new_assoc(struct hostapd_data *hapd, struct sta_info *sta)
{
	if (!hapd->iface->wifi_stats)
		return;
	wifi_stats_forget_sta(hapd->iface->wifi_stats, sta);
}


/*
 * The buffer goes with its sta_info. When ML reconfiguration removes the
 * association link, the new association link's sta_info gets a buffer of its
 * own, and a run of its own, at the next collection.
 */
void wifi_stats_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
{
	if (!hapd->iface->wifi_stats)
		return;
	wifi_stats_forget_sta(hapd->iface->wifi_stats, sta);
}


/*
 * Fold the per-link statistics of an MLD station into the top-level fields,
 * as the draft's "the aggregate across all links". Counters are summed. Bit
 * rates are summed over the links that carried frames since the baselines in
 * sb, the previous sample's counters (an idle EMLSR link holds a stale rate).
 * RSSI is the best link's, as signals of different bands do not average.
 * With no link moving, the best link's values stand in and
 * wifi_stats_drop_stale() keeps them out of the aggregate. Without per-link
 * statistics or sb, the MLD level or best-link values are used as they are.
 */
static void wifi_stats_combine_links(const struct wifi_stats_sta_buf *sb,
				     struct hostap_sta_driver_data *data)
{
	unsigned long rx = 0, tx = 0, retry = 0, failed = 0;
	unsigned long tx_rate = 0, rx_rate = 0, best_tx = 0, best_rx = 0;
	int signal = 0, best_signal = 0;
	int link;

	if (!data->valid_links)
		return;

	for (link = 0; link < MAX_NUM_MLD_LINKS; link++) {
		const struct hostap_sta_link_driver_data *ld =
			&data->links[link];
		bool rx_moved, tx_moved;

		if (!(data->valid_links & BIT(link)))
			continue;
		rx_moved = sb && ld->rx_packets != sb->prev_link[link].rx;
		tx_moved = sb && ld->tx_packets != sb->prev_link[link].tx;

		rx += ld->rx_packets;
		tx += ld->tx_packets;
		retry += ld->tx_retry_count;
		failed += ld->tx_retry_failed;
		if (tx_moved)
			tx_rate += ld->current_tx_rate;
		if (rx_moved) {
			rx_rate += ld->current_rx_rate;
			if (ld->signal && (!signal || ld->signal > signal))
				signal = ld->signal;
		}
		if (ld->current_tx_rate > best_tx)
			best_tx = ld->current_tx_rate;
		if (ld->current_rx_rate > best_rx)
			best_rx = ld->current_rx_rate;
		if (ld->signal && (!best_signal || ld->signal > best_signal))
			best_signal = ld->signal;
	}

	/* link IDs without counters: nothing to combine */
	if (!rx && !tx)
		return;

	data->rx_packets = rx;
	data->tx_packets = tx;
	data->tx_retry_count = retry;
	data->tx_retry_failed = failed;
	data->current_tx_rate = tx_rate ? tx_rate : best_tx;
	data->current_rx_rate = rx_rate ? rx_rate : best_rx;
	data->signal = signal ? signal : best_signal;
}


/* The per-link counters the next sample is compared with */
static void wifi_stats_store_link_baselines(
	struct wifi_stats_sta_buf *sb,
	const struct hostap_sta_driver_data *data)
{
	int link;

	if (!data->valid_links)
		return;

	for (link = 0; link < MAX_NUM_MLD_LINKS; link++) {
		const struct hostap_sta_link_driver_data *ld =
			&data->links[link];

		if (!(data->valid_links & BIT(link)))
			continue;
		sb->prev_link[link].rx = ld->rx_packets;
		sb->prev_link[link].tx = ld->tx_packets;
		sb->prev_link[link].retry = ld->tx_retry_count;
		sb->prev_link[link].failed = ld->tx_retry_failed;
	}
	sb->prev_link_mask = data->valid_links & (BIT(MAX_NUM_MLD_LINKS) - 1);
}


/*
 * Zero the signal and rates in the sample unless fresh: they are the
 * values of the last frame, so new only if frames moved in that direction
 * since the previous sample. The first sample has no baseline and its counters
 * cover the handshake. Rates are folded only if the port was authorized at
 * both samples, as the frames between include EAPOL at a basic rate. The raw
 * values are what sb->last keeps, which this must read before it is replaced.
 */
static void wifi_stats_drop_stale(struct wifi_stats_sta_buf *sb,
				  const struct sta_info *sta,
				  const struct hostap_sta_driver_data *data,
				  struct wifi_stats_sample *sample)
{
	bool authorized = sta->flags & WLAN_STA_AUTHORIZED;
	bool have_prev = os_reltime_initialized(&sb->last.timestamp);
	bool rx_fresh = have_prev && data->rx_packets != sb->prev_rx_packets;
	bool tx_fresh = have_prev && data->tx_packets != sb->last.tx_packets;
	bool rates_ok = authorized && sb->prev_authorized;

	sb->prev_authorized = authorized;
	sb->prev_rx_packets = data->rx_packets;

	if (!rx_fresh)
		sample->signal = 0;
	if (!rx_fresh || !rates_ok)
		sample->current_rx_rate = 0;
	if (!tx_fresh || !rates_ok)
		sample->current_tx_rate = 0;
}


static bool wifi_stats_collects_sta(struct hostapd_data *bss,
				    struct sta_info *sta)
{
	if (!(sta->flags & WLAN_STA_ASSOC))
		return false;
#ifdef CONFIG_IEEE80211BE
	/* The MLD association link returns all links' stats */
	if (ap_sta_is_mld(bss, sta) &&
	    sta->mld_assoc_link_id != bss->mld_link_id)
		return false;
#endif /* CONFIG_IEEE80211BE */
	return true;
}


static struct wifi_stats_sta_buf *
wifi_stats_sta_buf_get(struct wifi_stats_ctx *ctx, struct sta_info *sta)
{
	if (!sta->wifi_stats)
		wifi_stats_sta_buf_alloc(ctx, sta);
	return sta->wifi_stats;
}


/*
 * An MLD station's aggregates describe one set of links whose counters only
 * grew: a link added or removed (also removed and added again within one
 * interval) or a counter that went backwards starts a new run.
 */
static bool wifi_stats_links_restarted(
	const struct wifi_stats_sta_buf *sb,
	const struct hostap_sta_driver_data *data)
{
	unsigned int mask = data->valid_links & (BIT(MAX_NUM_MLD_LINKS) - 1);
	int link;

	if (!mask || !sb->prev_link_mask)
		return false;
	if (mask != sb->prev_link_mask)
		return true;
	for (link = 0; link < MAX_NUM_MLD_LINKS; link++) {
		const struct hostap_sta_link_driver_data *ld =
			&data->links[link];
		const struct wifi_stats_link_counters *prev =
			&sb->prev_link[link];

		if ((mask & BIT(link)) &&
		    (ld->rx_packets < prev->rx || ld->tx_packets < prev->tx ||
		     ld->tx_retry_count < prev->retry ||
		     ld->tx_retry_failed < prev->failed))
			return true;
	}
	return false;
}


/* The one sample of a collection, whichever driver read delivered the data */
static void wifi_stats_add_sample(struct wifi_stats_ctx *ctx,
				  struct hostapd_data *bss,
				  struct sta_info *sta,
				  struct wifi_stats_sta_buf *sb,
				  const struct hostap_sta_driver_data *data,
				  const struct os_reltime *now)
{
	struct hostap_sta_driver_data combined;
	struct wifi_stats_sample sample, raw;

	if (wifi_stats_links_restarted(sb, data)) {
		wifi_stats_forget_sta(ctx, sta);
		sb = wifi_stats_sta_buf_get(ctx, sta);
		if (!sb)
			return;
	}

	sb->sampled = true;
	os_memcpy(&combined, data, sizeof(combined));
	wifi_stats_combine_links(sb, &combined);
	wifi_stats_store_link_baselines(sb, &combined);

	wifi_stats_sample_set(&sample, &combined, now);
	raw = sample;
	wifi_stats_drop_stale(sb, sta, &combined, &sample);
	sb->last = raw;

	if (ctx->span_mode == WIFI_STATS_SPAN_REPORT) {
		wifi_stats_accum_collect(ctx, sb, &sample, now,
					 wifi_stats_report_bound(ctx, bss,
								 sta));
	} else {
		/* AVG-EXP is one filter for the association, as in REPORT */
		wifi_stats_accum_collect(ctx, sb, &sample, now, 0);
		wifi_stats_circular_push(&sb->buf, &sample);
	}
}


struct wifi_stats_dump {
	struct wifi_stats_ctx *ctx;
	struct hostapd_data *bss;
	const struct os_reltime *now;
};


/*
 * The links of an AP MLD share a driver interface, so the dump requested for
 * one link BSS also lists the stations of the others.
 */
static void wifi_stats_dump_cb(void *ctx, const u8 *addr,
			       const struct hostap_sta_driver_data *data)
{
	struct wifi_stats_dump *dump = ctx;
	struct sta_info *sta = ap_get_sta(dump->bss, addr);
	struct wifi_stats_sta_buf *sb;

	if (!sta || !wifi_stats_collects_sta(dump->bss, sta))
		return;
	sb = wifi_stats_sta_buf_get(dump->ctx, sta);
	if (!sb || sb->sampled)
		return;
	wifi_stats_add_sample(dump->ctx, dump->bss, sta, sb, data, dump->now);
}


static void wifi_stats_collect(struct wifi_stats_ctx *ctx)
{
	struct hostapd_iface *iface = ctx->iface;
	struct wifi_stats_sta_buf *sb;
	struct os_reltime now;
	size_t bss_idx;

	if (wifi_stats_all_metrics_none(ctx))
		return;

	/*
	 * The timer runs from the start of interface setup, which can complete
	 * asynchronously, and it outlives a setup that fails.
	 */
	if (iface->state != HAPD_IFACE_ENABLED)
		return;

	os_get_reltime(&now);

	/*
	 * A second sample in one collection would count twice in an average
	 * and step the EWMA twice.
	 */
	for (sb = ctx->sta_bufs; sb; sb = sb->next)
		sb->sampled = false;

	for (bss_idx = 0; bss_idx < iface->num_bss; bss_idx++) {
		struct hostapd_data *bss = iface->bss[bss_idx];
		struct wifi_stats_dump dump = {
			.ctx = ctx,
			.bss = bss,
			.now = &now,
		};
		struct sta_info *sta;

		/*
		 * A BSS that is not started has the first BSS's drv_priv until
		 * hostapd_setup_bss() and none after hostapd_free_hapd_data()
		 */
		if (!bss->started || !bss->drv_priv)
			continue;

		hostapd_drv_read_all_sta_data(bss, wifi_stats_dump_cb, &dump);

		/*
		 * What the dump did not deliver: a station on an AP_VLAN
		 * interface, any station if the driver cannot dump or the
		 * request failed.
		 */
		for (sta = bss->sta_list; sta; sta = sta->next) {
			struct hostap_sta_driver_data sta_data;

			if (!wifi_stats_collects_sta(bss, sta))
				continue;
			sb = wifi_stats_sta_buf_get(ctx, sta);
			if (!sb || sb->sampled)
				continue;

			os_memset(&sta_data, 0, sizeof(sta_data));
			if (hostapd_drv_read_sta_data(bss, &sta_data,
						      sta->addr)) {
				wpa_printf(MSG_DEBUG,
					   "wifi_stats: Failed to read STA data for "
					   MACSTR, MAC2STR(sta->addr));
				continue;
			}

			wifi_stats_add_sample(ctx, bss, sta, sb, &sta_data,
					      &now);
		}
	}
}


static void wifi_stats_timer_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct wifi_stats_ctx *ctx = eloop_ctx;

	wifi_stats_collect(ctx);

	if (eloop_register_timeout(ctx->collection_interval, 0,
				   wifi_stats_timer_cb, ctx, NULL) < 0) {
		wpa_printf(MSG_WARNING,
			   "wifi_stats: Failed to reschedule collection timer, stopping collection");
		ctx->timer_active = 0;
	}
}


static int wifi_stats_start_timer(struct wifi_stats_ctx *ctx)
{
	wifi_stats_stop_timer(ctx);

	ctx->timer_active = 1;

	wpa_printf(MSG_DEBUG,
		   "wifi_stats: Starting collection timer (interval: %u seconds)",
		   ctx->collection_interval);

	if (eloop_register_timeout(ctx->collection_interval, 0,
				   wifi_stats_timer_cb, ctx, NULL) < 0) {
		wpa_printf(MSG_WARNING,
			   "wifi_stats: Failed to start collection timer");
		ctx->timer_active = 0;
		return -1;
	}

	return 0;
}


/*
 * Statistics are collected only while enabled. Disabling ends every period:
 * a station that stays associated starts a new one when collection resumes,
 * as nothing was sampled in between.
 */
static int wifi_stats_set_enabled(struct wifi_stats_ctx *ctx, bool enabled)
{
	if (!enabled) {
		wifi_stats_stop_timer(ctx);
		wifi_stats_free_all_bufs(ctx);
		return 0;
	}

	/* Restarting would push the next collection out by an interval */
	if (ctx->timer_active)
		return 0;
	return wifi_stats_start_timer(ctx);
}


/* Whether statistics are collected, whatever the configuration says */
static bool wifi_stats_enabled(const struct wifi_stats_ctx *ctx)
{
	return ctx && ctx->timer_active;
}


/*
 * The AGGR production, "(ALGO SPAN)", or an empty string if not aggregated.
 * Per draft-ietf-radext-connectinfo-02 AVG-EXP reports the weight, not a span:
 * AGGR = ALGO SP ( WINDOW / (WEIGHT ["-" SAMPLE]) ).
 * SAMPLE is the interval in ms; it has four digits, so it is omitted above 9 s.
 */
static const char * wifi_stats_aggr(struct wifi_stats_ctx *ctx,
				    const struct wifi_stats_agg_result *res,
				    char *buf, size_t buf_len)
{
	unsigned int sample_ms = ctx->collection_interval * 1000;
	char span[16];

	if (res->actual_points <= 1)
		return "";
	if (res->algorithm != WIFI_STATS_AGG_AVG_EXP)
		os_snprintf(span, sizeof(span), "%s", res->timeframe_str);
	else if (sample_ms <= WIFI_STATS_MAX_SAMPLE_MS)
		os_snprintf(span, sizeof(span), "%u-%u", ctx->ewma_weight,
			    sample_ms);
	else
		os_snprintf(span, sizeof(span), "%u", ctx->ewma_weight);
	os_snprintf(buf, buf_len, "(%s %s)",
		    wifi_stats_agg_type_to_str(res->algorithm), span);
	return buf;
}


static int wifi_stats_get_global_op_class(struct hostapd_data *hapd)
{
	const char *country;
	u8 op_class = 0, channel = 0;
	int freq;

	country = hapd->iconf->country[0] ? hapd->iconf->country : NULL;

	if (hapd->iconf->op_class)
		return country_to_global_op_class(country,
						  hapd->iconf->op_class);

	freq = hapd->iface->freq;
	if (!freq)
		return 0;

	if (ieee80211_freq_to_channel_ext(freq, hapd->iconf->secondary_channel,
					  hostapd_get_oper_chwidth(hapd->iconf),
					  &op_class, &channel) ==
	    NUM_HOSTAPD_MODES)
		return 0;

	return country_to_global_op_class(country, op_class);
}


static int wifi_stats_round_nearest(double value)
{
	return (int) (value < 0 ? value - 0.5 : value + 0.5);
}


static int wifi_stats_clamp_pct(double value)
{
	if (value < 0.0)
		return 0;
	if (value > 100.0)
		return 100;
	return wifi_stats_round_nearest(value);
}


static int wifi_stats_clamp_rssi(int dbm)
{
	if (dbm < -128)
		return -128;
	if (dbm > 0)
		return 0;
	return dbm;
}


static double wifi_stats_clamp_rate(double mbps)
{
	if (mbps < 0.0)
		return 0.0;
	if (mbps > 99999.9)
		return 99999.9;
	return mbps;
}


double wifi_stats_clamp_maxspeed(double mbps)
{
	if (mbps < 0.0)
		return 0.0;
	if (mbps > 99999.99)
		return 99999.99;
	return mbps;
}


/*
 * Whether a metric is emitted as the driver's latest value rather than as an
 * aggregate or not at all. The formatter reads the driver for no other
 * reason, and the emitters decide with the same function.
 */
static bool wifi_stats_instant(enum wifi_stats_metric_type metric,
			       const struct wifi_stats_agg_result *result)
{
	if (metric == WIFI_STATS_METRIC_FRAME_LOSS ||
	    metric == WIFI_STATS_METRIC_FRAME_RETRY)
		return result->algorithm == WIFI_STATS_AGG_NONE;
	return result->actual_points <= 1;
}


int wifi_stats_emit_bitrate(char **pos, char *end,
			    enum wifi_stats_metric_type metric,
			    const struct wifi_stats_agg_result *result,
			    const struct wifi_stats_sample *latest,
			    struct wifi_stats_ctx *ctx)
{
	char aggr_buf[32];
	int written = 0;
	double mbps;

	if (wifi_stats_instant(metric, result)) {
		if (!latest)
			return 0;
		mbps = extract_station_metric(latest, metric);
	} else {
		mbps = result->value;
	}
	mbps = wifi_stats_clamp_rate(mbps / 1000.0);

	if (mbps >= 0.05)
		written = os_snprintf(*pos, end - *pos, " %s:%.1f%s",
				      metric_names[metric], mbps,
				      wifi_stats_aggr(ctx, result, aggr_buf,
						      sizeof(aggr_buf)));
	if (written && os_snprintf_error(end - *pos, written))
		return -1;
	*pos += written;
	return 0;
}


int wifi_stats_emit_rssi(char **pos, char *end,
			 const struct wifi_stats_agg_result *result,
			 const struct wifi_stats_sample *latest,
			 struct wifi_stats_ctx *ctx)
{
	char aggr_buf[32];
	int written = 0;
	int dbm;

	if (wifi_stats_instant(WIFI_STATS_METRIC_RSSI, result)) {
		if (!latest)
			return 0;
		dbm = latest->signal;
	} else {
		dbm = wifi_stats_round_nearest(result->value);
	}
	dbm = wifi_stats_clamp_rssi(dbm);

	if (dbm != 0)
		written = os_snprintf(*pos, end - *pos, " RSSI:%d%s", dbm,
				      wifi_stats_aggr(ctx, result, aggr_buf,
						      sizeof(aggr_buf)));
	if (written && os_snprintf_error(end - *pos, written))
		return -1;
	*pos += written;
	return 0;
}


int wifi_stats_emit_pct(char **pos, char *end,
			enum wifi_stats_metric_type metric,
			const struct wifi_stats_agg_result *result,
			const struct wifi_stats_sample *latest,
			struct wifi_stats_ctx *ctx)
{
	char aggr_buf[32];
	int written = 0;

	if (wifi_stats_instant(metric, result)) {
		double numerator, denominator;

		if (!latest)
			return 0;
		numerator = extract_station_metric(latest, metric);
		denominator = wifi_stats_metric_base(latest, metric);
		if (denominator >= WIFI_STATS_ACC_MIN_FRAMES)
			written = os_snprintf(*pos, end - *pos, " %s:%d",
					      metric_names[metric],
					      wifi_stats_clamp_pct(
						      numerator * 100 /
						      denominator));
	} else if (result->actual_points > 1 &&
		   result->base_delta >= WIFI_STATS_ACC_MIN_FRAMES) {
		written = os_snprintf(*pos, end - *pos, " %s:%d%s",
				      metric_names[metric],
				      wifi_stats_clamp_pct(result->value),
				      wifi_stats_aggr(ctx, result, aggr_buf,
						      sizeof(aggr_buf)));
	}
	if (written && os_snprintf_error(end - *pos, written))
		return -1;
	*pos += written;
	return 0;
}


/*
 * Returns 1 when the token does not fit. Only Global-OC is dropped rather
 * than failing the string: an AP MLD can have more links than 253 octets hold.
 */
static int wifi_stats_emit_goc(char **pos, char *end,
			       struct hostapd_data *hapd, int link_id)
{
	int goc = wifi_stats_get_global_op_class(hapd);
	int written;

	if (goc <= 0 || goc > 255)
		return 0;
	if (link_id >= 0)
		written = os_snprintf(*pos, end - *pos,
				      " Global-OC:%d(Link-ID:%d)", goc,
				      link_id);
	else
		written = os_snprintf(*pos, end - *pos, " Global-OC:%d", goc);
	if (os_snprintf_error(end - *pos, written)) {
		**pos = '\0';
		return 1;
	}
	*pos += written;
	return 0;
}


/* An AP MLD transmits on all its links at once: MAXSPEED is their sum */
static double wifi_stats_maxspeed(struct hostapd_data *hapd)
{
#ifdef CONFIG_IEEE80211BE
	if (hapd->conf->mld_ap && hapd->mld) {
		struct hostapd_data *link_bss;
		double sum = 0.0;

		for_each_mld_link(link_bss, hapd)
			sum += wifi_stats_bss_maxspeed(link_bss);
		return sum;
	}
#endif /* CONFIG_IEEE80211BE */
	return wifi_stats_bss_maxspeed(hapd);
}


int wifi_stats_connect_info(struct hostapd_data *hapd, struct sta_info *sta,
			    char *buf, size_t buflen)
{
	struct wifi_stats_ctx *ctx = hapd->iface->wifi_stats;
	struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT];
	struct wifi_stats_agg_result *rssi, *tx, *rx, *loss, *retry;
	struct hostap_sta_driver_data sta_data;
	struct wifi_stats_sample live;
	const struct wifi_stats_sample *latest = NULL;
	struct wifi_stats_sta_buf *sta_buf, *own_buf;
	struct wifi_stats_ctx *own_ctx;
	bool empty_period;
	unsigned int caller_bit;
	struct os_reltime now;
	enum wifi_stats_amendment amd;
	char *pos, *end;
	int written, freq, i;
	u8 channel_num = 0;

	if (!wifi_stats_enabled(ctx))
		return -1;

	caller_bit = wifi_stats_link_bit(hapd);
	own_ctx = ctx;
	own_buf = sta->wifi_stats;

#ifdef CONFIG_IEEE80211BE
	/* An MLD station is collected, and reported, on its association link */
	{
		struct hostapd_data *assoc;
		struct sta_info *assoc_sta;

		assoc = wifi_stats_mld_assoc_link(hapd, sta, &assoc_sta);
		if (assoc && assoc->iface->wifi_stats) {
			ctx = assoc->iface->wifi_stats;
			hapd = assoc;
			sta = assoc_sta;
		}
	}
#endif /* CONFIG_IEEE80211BE */

	sta_buf = sta->wifi_stats;
	/*
	 * ML reconfiguration moves the association link before the old one's
	 * Accounting-Stop; until a collection gives the new association link
	 * a buffer, that Stop is formatted from the old link's own.
	 */
	if (!sta_buf && own_buf) {
		ctx = own_ctx;
		sta_buf = own_buf;
	}

	/*
	 * A link that already reported the period sees an empty one. Only a
	 * REPORT span has periods: it alone sets the mask.
	 */
	empty_period = sta_buf && (sta_buf->signalled_links & caller_bit);

	if (sta_buf && !empty_period) {
		wifi_stats_aggregate_for_station(ctx, sta_buf, results);
	} else {
		os_memset(results, 0, sizeof(results));
		for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
			results[i].algorithm = ctx->agg_config[i];
	}

	pos = buf;
	end = buf + (buflen > WIFI_STATS_MAX_CONNECT_INFO_LEN + 1 ?
		     WIFI_STATS_MAX_CONNECT_INFO_LEN + 1 : buflen);

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (wifi_stats_instant(i, &results[i]))
			break;
	}

	/*
	 * The raw driver values, not freshness-gated, for the metrics emitted
	 * without an aggregate. One that cannot be read is left out, and what
	 * was collected is still reported.
	 */
	if (i < WIFI_STATS_METRIC_COUNT) {
		os_get_reltime(&now);
		os_memset(&sta_data, 0, sizeof(sta_data));
		if (sta_buf &&
		    os_reltime_initialized(&sta_buf->last.timestamp) &&
		    !os_reltime_expired(&now, &sta_buf->last.timestamp,
					WIFI_STATS_INSTANT_MAX_AGE)) {
			latest = &sta_buf->last;
		} else if (!hostapd_drv_read_sta_data(hapd, &sta_data,
						      sta->addr)) {
			wifi_stats_combine_links(sta_buf, &sta_data);
			wifi_stats_sample_set(&live, &sta_data, &now);
			latest = &live;
		} else if (!sta_buf) {
			return -1;
		}
	}

	amd = wifi_stats_bss_amendment(hapd);

	freq = hapd->iface->freq;
	if (freq)
		ieee80211_freq_to_chan(freq, &channel_num);

	written = os_snprintf(pos, end - pos, "CONNECT %.2f Mbps 802.11%s",
			      wifi_stats_clamp_maxspeed(
				      wifi_stats_maxspeed(hapd)),
			      wifi_stats_amendment_str[amd]);
	if (os_snprintf_error(end - pos, written))
		return -1;
	pos += written;

	if (channel_num > 0) {
		written = os_snprintf(pos, end - pos, " Channel:%d",
				      (int) channel_num);
		if (os_snprintf_error(end - pos, written))
			return -1;
		pos += written;
	}

	rssi = &results[WIFI_STATS_METRIC_RSSI];
	if (wifi_stats_emit_rssi(&pos, end, rssi, latest, ctx))
		return -1;

	tx = &results[WIFI_STATS_METRIC_TX_BITRATE];
	if (wifi_stats_emit_bitrate(&pos, end, WIFI_STATS_METRIC_TX_BITRATE, tx,
				    latest, ctx))
		return -1;

	rx = &results[WIFI_STATS_METRIC_RX_BITRATE];
	if (wifi_stats_emit_bitrate(&pos, end, WIFI_STATS_METRIC_RX_BITRATE, rx,
				    latest, ctx))
		return -1;

	loss = &results[WIFI_STATS_METRIC_FRAME_LOSS];
	if (wifi_stats_emit_pct(&pos, end, WIFI_STATS_METRIC_FRAME_LOSS, loss,
				latest, ctx))
		return -1;

	retry = &results[WIFI_STATS_METRIC_FRAME_RETRY];
	if (wifi_stats_emit_pct(&pos, end, WIFI_STATS_METRIC_FRAME_RETRY, retry,
				latest, ctx))
		return -1;

#ifdef CONFIG_IEEE80211BE
	/*
	 * One Global-OC per link per the draft, the association link first so
	 * that it survives an overflow and pairs with the Channel attribute.
	 */
	if (ap_sta_is_mld(hapd, sta)) {
		int link_id;

		if (wifi_stats_emit_goc(&pos, end, hapd, hapd->mld_link_id))
			return (int) (pos - buf);
		for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
			struct hostapd_data *link_bss;

			/* a rejected link stays valid with a failure status */
			if (link_id == hapd->mld_link_id ||
			    !sta->mld_info.links[link_id].valid ||
			    sta->mld_info.links[link_id].status !=
			    WLAN_STATUS_SUCCESS)
				continue;
			link_bss = hostapd_mld_get_link_bss(hapd, link_id);
			if (link_bss &&
			    wifi_stats_emit_goc(&pos, end, link_bss, link_id))
				break;
		}
		return (int) (pos - buf);
	}
#endif /* CONFIG_IEEE80211BE */

	wifi_stats_emit_goc(&pos, end, hapd, -1);
	return (int) (pos - buf);
}


/*
 * The span, the interval, and the window are applied together since the size
 * of the buffers depends on all three.
 */
static void wifi_stats_set_params(struct wifi_stats_ctx *ctx,
				  enum wifi_stats_span_mode span,
				  unsigned int interval, unsigned int window)
{
	bool interval_changed, changed;

	interval_changed = interval != ctx->collection_interval;
	/*
	 * Samples taken under other settings do not describe the new ones, and
	 * a report mixing them would be misleading: start every station anew.
	 */
	changed = interval_changed || span != ctx->span_mode ||
		window != ctx->window_seconds;
	if (changed)
		wifi_stats_free_all_bufs(ctx);

	ctx->span_mode = span;
	ctx->collection_interval = interval;
	ctx->window_seconds = window;

	if (interval_changed && ctx->timer_active)
		wifi_stats_start_timer(ctx);

	wpa_printf(MSG_DEBUG, "wifi_stats: Set span=%s interval=%us window=%us",
		   span_mode_strings[span],
		   ctx->collection_interval, ctx->window_seconds);
}


/*
 * ACC is the ratio of two counter deltas: the only aggregate FrameLoss and
 * FrameRetry have, and undefined for the other metrics. NONE fits them all.
 */
bool wifi_stats_algorithm_valid(enum wifi_stats_metric_type metric,
				enum wifi_stats_agg_type algorithm)
{
	bool ratio = metric == WIFI_STATS_METRIC_FRAME_LOSS ||
		metric == WIFI_STATS_METRIC_FRAME_RETRY;

	if (metric >= WIFI_STATS_METRIC_COUNT ||
	    algorithm >= WIFI_STATS_AGG_COUNT)
		return false;
	if (algorithm == WIFI_STATS_AGG_NONE)
		return true;
	return (algorithm == WIFI_STATS_AGG_ACC) == ratio;
}


/*
 * The algorithms are applied together. Collection stops with every metric
 * NONE, so the statistics restart when "every metric is NONE" changes.
 */
static void wifi_stats_set_metrics(
	struct wifi_stats_ctx *ctx,
	const enum wifi_stats_agg_type algorithms[WIFI_STATS_METRIC_COUNT])
{
	bool was_all_none = wifi_stats_all_metrics_none(ctx);
	int i;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		ctx->agg_config[i] = algorithms[i];
		wpa_printf(MSG_DEBUG, "wifi_stats: Set metric %s=%s",
			   metric_names[i],
			   wifi_stats_agg_type_to_str(algorithms[i]));
	}

	if (was_all_none != wifi_stats_all_metrics_none(ctx))
		wifi_stats_free_all_bufs(ctx);
}


enum wifi_stats_span_mode wifi_stats_span_mode_from_str(const char *str)
{
	int i;

	for (i = 0; i < WIFI_STATS_SPAN_COUNT; i++) {
		if (os_strcmp(str, span_mode_strings[i]) == 0)
			return (enum wifi_stats_span_mode) i;
	}
	return WIFI_STATS_SPAN_COUNT;
}


static void wifi_stats_set_ewma_weight(struct wifi_stats_ctx *ctx,
				       unsigned int weight)
{
	ctx->ewma_weight = weight;
	wpa_printf(MSG_DEBUG, "wifi_stats: Set ewma_weight=%u (alpha=1/%u)",
		   weight, 1U << weight);
}


int wifi_stats_get_status(struct hostapd_iface *iface, char *buf,
			  size_t buflen)
{
	struct wifi_stats_ctx *ctx = iface->wifi_stats;
	char *pos = buf, *end = buf + buflen;
	int written;
	int i;

	if (!ctx)
		return -1;

	written = os_snprintf(pos, end - pos,
			      "interval=%u\n"
			      "window=%u\n"
			      "wba_enabled=%d\n"
			      "span=%s\n"
			      "ewma_weight=%u\n",
			      ctx->collection_interval, ctx->window_seconds,
			      wifi_stats_enabled(ctx),
			      span_mode_strings[ctx->span_mode],
			      ctx->ewma_weight);
	if (os_snprintf_error(end - pos, written))
		return -1;
	pos += written;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		written = os_snprintf(pos, end - pos, "%s=%s\n",
				      metric_names[i],
				      wifi_stats_agg_type_to_str(
					      ctx->agg_config[i]));
		if (os_snprintf_error(end - pos, written))
			return -1;
		pos += written;
	}

	return pos - buf;
}


void wifi_stats_reload_config(struct hostapd_iface *iface)
{
	enum wifi_stats_agg_type algorithms[WIFI_STATS_METRIC_COUNT];
	int i;

	if (!iface->wifi_stats)
		return;

	wifi_stats_set_params(iface->wifi_stats, iface->conf->wifi_stats_span,
			      iface->conf->wifi_stats_interval,
			      iface->conf->wifi_stats_wba_window);
	wifi_stats_set_ewma_weight(iface->wifi_stats,
				   iface->conf->wifi_stats_ewma_weight);

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (iface->conf->wifi_stats_metrics[i].configured)
			algorithms[i] =
				iface->conf->wifi_stats_metrics[i].algorithm;
		else
			algorithms[i] = wifi_stats_default_algorithm(i);
	}
	wifi_stats_set_metrics(iface->wifi_stats, algorithms);

	if (wifi_stats_set_enabled(iface->wifi_stats,
				   iface->conf->wifi_stats_wba_enabled) < 0)
		wpa_printf(MSG_WARNING, "wifi_stats: Failed to start timer");

	wpa_printf(MSG_DEBUG,
		   "wifi_stats: Applied config (enabled=%d interval=%u window=%u span=%s weight=%u)",
		   iface->conf->wifi_stats_wba_enabled,
		   iface->conf->wifi_stats_interval,
		   iface->conf->wifi_stats_wba_window,
		   span_mode_strings[iface->conf->wifi_stats_span],
		   iface->conf->wifi_stats_ewma_weight);
}


void wifi_stats_init(struct hostapd_iface *iface)
{
	if (!iface->wifi_stats)
		iface->wifi_stats = wifi_stats_ctx_new(iface);
	if (!iface->wifi_stats)
		wpa_printf(MSG_WARNING,
			   "wifi_stats: Failed to allocate context, continuing without stats");
	else
		wifi_stats_reload_config(iface);
}


void wifi_stats_deinit(struct hostapd_iface *iface)
{
	if (!iface->wifi_stats)
		return;

	wifi_stats_set_enabled(iface->wifi_stats, false);
	os_free(iface->wifi_stats);
	iface->wifi_stats = NULL;
}


const char * wifi_stats_agg_type_to_str(enum wifi_stats_agg_type type)
{
	return agg_type_strings[type];
}


enum wifi_stats_agg_type wifi_stats_agg_type_from_str(const char *str)
{
	int i;

	for (i = 0; i < WIFI_STATS_AGG_COUNT; i++) {
		if (os_strcasecmp(str, agg_type_strings[i]) == 0)
			return (enum wifi_stats_agg_type) i;
	}
	return WIFI_STATS_AGG_COUNT;
}


enum wifi_stats_metric_type wifi_stats_metric_type_from_str(const char *str)
{
	int i;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (os_strcasecmp(str, metric_names[i]) == 0)
			return (enum wifi_stats_metric_type) i;
	}
	return WIFI_STATS_METRIC_COUNT;
}
