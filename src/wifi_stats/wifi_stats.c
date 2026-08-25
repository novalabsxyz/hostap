/*
 * wifi_stats.c - Periodic WiFi statistics collection for hostapd
 * Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
 *
 * This module provides logic to periodically collect per-station statistics
 * from the driver, store them in per-station circular buffers, and format
 * Connect-Info attributes with aggregated metrics per
 * draft-grayson-connectinfo-10.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "eloop.h"
#include "ap/hostapd.h"
#include "ap/sta_info.h"
#include "ap/ap_drv_ops.h"
#include "ap/ap_config.h"
#include "drivers/driver.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "wifi_stats/wifi_stats.h"

struct wifi_stats_sample {
	struct hostap_sta_driver_data data;
	struct os_time timestamp;
};

struct wifi_stats_circular {
	struct wifi_stats_sample *entries;
	size_t max_len;
	size_t head;
	size_t count;
};

/*
 * Incremental per-metric state used in WIFI_STATS_SPAN_REPORT mode. Every
 * algorithm implemented here is a streaming statistic, so no sample history
 * is needed
 */
struct wifi_stats_accum {
	double min;
	double max;
	double sum;
	double ewma;
	int ewma_valid;
	double first_val;
	double first_base;
	double last_val;
	double last_base;
	unsigned int count;
	struct os_time first_ts;
	struct os_time last_ts;
	struct os_time base_ts;
};

struct wifi_stats_sta_buf {
	u8 addr[ETH_ALEN];
	struct wifi_stats_circular buf;
	struct wifi_stats_accum accum[WIFI_STATS_METRIC_COUNT];
	struct hostap_sta_driver_data last_data;
	int last_data_valid;
	struct os_time last_update;
	struct os_time period_start;
	struct wifi_stats_sta_buf *next;
};

struct wifi_stats_agg_result {
	double value;
	wifi_stats_agg_type_t algorithm;
	int actual_points;
	char timeframe_str[16];
};

struct wifi_stats_ctx {
	unsigned int collection_interval;
	unsigned int window_seconds;
	unsigned int ewma_weight;
	wifi_stats_span_mode_t span_mode;
	struct hostapd_iface *iface;
	int timer_active;
	int aggregation_suppressed;
	wifi_stats_agg_type_t agg_config[WIFI_STATS_METRIC_COUNT];
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

	buf->entries = os_zalloc(sizeof(struct wifi_stats_sample) * max_len);
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


static int wifi_stats_circular_resize(struct wifi_stats_circular *buf,
				      size_t new_max_len)
{
	struct wifi_stats_sample *new_entries;
	size_t copy_count, skip;

	if (new_max_len == buf->max_len)
		return 0;

	if (new_max_len == 0) {
		wifi_stats_circular_free(buf);
		buf->max_len = 0;
		buf->head = 0;
		buf->count = 0;
		return 0;
	}

	new_entries = os_zalloc(sizeof(struct wifi_stats_sample) * new_max_len);
	if (!new_entries)
		return -1;

	/* Copy existing entries oldest-first; at most two contiguous chunks */
	copy_count = buf->count < new_max_len ? buf->count : new_max_len;
	skip = buf->count > copy_count ? buf->count - copy_count : 0;

	if (copy_count > 0) {
		size_t oldest = (buf->head - buf->count + skip +
				 buf->max_len) % buf->max_len;
		size_t tail_len = buf->max_len - oldest;

		if (tail_len >= copy_count) {
			os_memcpy(new_entries, &buf->entries[oldest],
				  copy_count * sizeof(struct wifi_stats_sample));
		} else {
			os_memcpy(new_entries, &buf->entries[oldest],
				  tail_len * sizeof(struct wifi_stats_sample));
			os_memcpy(&new_entries[tail_len], buf->entries,
				  (copy_count - tail_len) *
				  sizeof(struct wifi_stats_sample));
		}
	}

	os_free(buf->entries);
	buf->entries = new_entries;
	buf->max_len = new_max_len;
	buf->count = copy_count;
	buf->head = copy_count % new_max_len;

	return 0;
}


static void wifi_stats_circular_push(struct wifi_stats_circular *buf,
				     const struct wifi_stats_sample *entry)
{
	if (!buf->entries || buf->max_len == 0)
		return;
	buf->entries[buf->head] = *entry;
	buf->head = (buf->head + 1) % buf->max_len;
	if (buf->count < buf->max_len)
		buf->count++;
}


static struct wifi_stats_sample *wifi_stats_circular_get(
	const struct wifi_stats_circular *buf, size_t idx)
{
	if (!buf->entries || idx >= buf->max_len)
		return NULL;
	return &buf->entries[idx];
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

static void wifi_stats_check_degenerate_config(struct wifi_stats_ctx *ctx)
{
	int suppressed;

	if (ctx->span_mode != WIFI_STATS_SPAN_WINDOW) {
		ctx->aggregation_suppressed = 0;
		return;
	}

	suppressed = ctx->window_seconds <= ctx->collection_interval;
	if (suppressed == ctx->aggregation_suppressed)
		return;

	ctx->aggregation_suppressed = suppressed;
	if (suppressed)
		wpa_printf(MSG_WARNING,
			   "wifi_stats: window (%us) <= interval (%us), "
			   "aggregation suppressed (reporting instantaneous values)",
			   ctx->window_seconds, ctx->collection_interval);
	else
		wpa_printf(MSG_WARNING,
			   "wifi_stats: window (%us) > interval (%us), aggregation resumed",
			   ctx->window_seconds, ctx->collection_interval);
}


static size_t wifi_stats_compute_buf_max(struct wifi_stats_ctx *ctx)
{
	if (wifi_stats_all_metrics_none(ctx))
		return 0;
	if (ctx->span_mode == WIFI_STATS_SPAN_REPORT)
		return 0;
	if (ctx->aggregation_suppressed)
		return 0;
	if (ctx->collection_interval == 0)
		return 0;
	return ctx->window_seconds / ctx->collection_interval + 1;
}


static struct wifi_stats_sta_buf *wifi_stats_find_sta_buf(
	struct wifi_stats_ctx *ctx, const u8 *addr)
{
	struct wifi_stats_sta_buf *sb;

	for (sb = ctx->sta_bufs; sb; sb = sb->next) {
		if (os_memcmp(sb->addr, addr, ETH_ALEN) == 0)
			return sb;
	}
	return NULL;
}


static struct wifi_stats_sta_buf *wifi_stats_sta_buf_alloc(
	struct wifi_stats_ctx *ctx, const u8 *addr)
{
	struct wifi_stats_sta_buf *sb;
	size_t max_len;

	max_len = wifi_stats_compute_buf_max(ctx);

	sb = os_zalloc(sizeof(*sb));
	if (!sb)
		return NULL;

	os_memcpy(sb->addr, addr, ETH_ALEN);
	if (wifi_stats_circular_init(&sb->buf, max_len) < 0) {
		os_free(sb);
		return NULL;
	}

	sb->next = ctx->sta_bufs;
	ctx->sta_bufs = sb;

	wpa_printf(MSG_DEBUG, "wifi_stats: Allocated buffer for " MACSTR
		   " (max_len=%zu)", MAC2STR(addr), max_len);

	return sb;
}


static void wifi_stats_clear_sta_refs(struct hostapd_iface *iface,
				      struct wifi_stats_sta_buf *sb)
{
	size_t j;
	struct sta_info *sta;

	if (!iface || !iface->bss)
		return;
	for (j = 0; j < iface->num_bss; j++) {
		if (!iface->bss[j])
			continue;
		for (sta = iface->bss[j]->sta_list; sta; sta = sta->next) {
			if (sta->wifi_stats == sb)
				sta->wifi_stats = NULL;
		}
	}
}

static void wifi_stats_unlink_and_free_buf(struct wifi_stats_sta_buf **pp,
					   struct hostapd_iface *iface)
{
	struct wifi_stats_sta_buf *sb = *pp;

	*pp = sb->next;
	wifi_stats_clear_sta_refs(iface, sb);
	wifi_stats_circular_free(&sb->buf);
	os_free(sb);
}


static void wifi_stats_prune_stale_bufs(struct wifi_stats_ctx *ctx,
					struct hostapd_iface *iface)
{
	struct wifi_stats_sta_buf *sb;
	struct wifi_stats_sta_buf **pp;
	struct os_time now;
	size_t newest_idx;
	struct wifi_stats_sample *newest;
	long age;

	os_get_time(&now);

	pp = &ctx->sta_bufs;
	while (*pp) {
		sb = *pp;

		if (ctx->span_mode == WIFI_STATS_SPAN_REPORT ||
		    sb->buf.max_len == 0) {
			age = sb->last_update.sec ?
				now.sec - sb->last_update.sec :
				(long)ctx->window_seconds + 1;
			if (age > (long)ctx->window_seconds) {
				wifi_stats_unlink_and_free_buf(pp, iface);
				continue;
			}
			pp = &sb->next;
			continue;
		}

		if (sb->buf.count == 0) {
			wifi_stats_unlink_and_free_buf(pp, iface);
			continue;
		}

		newest_idx = (sb->buf.head - 1 + sb->buf.max_len) %
			     sb->buf.max_len;
		newest = wifi_stats_circular_get(&sb->buf, newest_idx);
		if (!newest) {
			pp = &sb->next;
			continue;
		}
		age = now.sec - newest->timestamp.sec;
		if (age > (long)ctx->window_seconds) {
			wifi_stats_unlink_and_free_buf(pp, iface);
			continue;
		}

		pp = &sb->next;
	}
}


static void wifi_stats_resize_all_bufs(struct wifi_stats_ctx *ctx)
{
	struct wifi_stats_sta_buf *sb;
	size_t new_max;

	new_max = wifi_stats_compute_buf_max(ctx);

	for (sb = ctx->sta_bufs; sb; sb = sb->next) {
		if (sb->buf.max_len != new_max &&
		    wifi_stats_circular_resize(&sb->buf, new_max) < 0)
			wpa_printf(MSG_WARNING,
				   "wifi_stats: Failed to resize buffer for " MACSTR,
				   MAC2STR(sb->addr));
	}
}


/* Algorithm defaults per draft-grayson-connectinfo-10 Section 4.2 */
wifi_stats_agg_type_t wifi_stats_default_algorithm(
	wifi_stats_metric_type_t metric)
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

static const char *agg_type_strings[WIFI_STATS_AGG_COUNT] = {
	[WIFI_STATS_AGG_MIN] = "MIN",
	[WIFI_STATS_AGG_MAX] = "MAX",
	[WIFI_STATS_AGG_AVG_LIN] = "AVG-LIN",
	[WIFI_STATS_AGG_AVG_EXP] = "AVG-EXP",
	[WIFI_STATS_AGG_ACC] = "ACC",
	[WIFI_STATS_AGG_NONE] = "NONE"
};

static double aggregate_avg_linear(double *data, int count)
{
	double sum = 0.0;
	int i;

	if (count <= 0)
		return 0.0;

	for (i = 0; i < count; i++)
		sum += data[i];

	return sum / count;
}


static double aggregate_max(double *data, int count)
{
	double max_val;
	int i;

	if (count <= 0)
		return 0.0;

	max_val = data[0];
	for (i = 1; i < count; i++) {
		if (data[i] > max_val)
			max_val = data[i];
	}
	return max_val;
}


static double aggregate_min(double *data, int count)
{
	double min_val;
	int i;

	if (count <= 0)
		return 0.0;

	min_val = data[0];
	for (i = 1; i < count; i++) {
		if (data[i] < min_val)
			min_val = data[i];
	}
	return min_val;
}


static double aggregate_avg_exponential(
	double *data, int count, unsigned int weight)
{
	double alpha;
	double ewma;
	int i;

	if (count <= 0)
		return 0.0;
	if (count == 1)
		return data[0];

	alpha = 1.0 / (double)(1u << weight);
	ewma = data[0];
	for (i = 1; i < count; i++)
		ewma = alpha * data[i] + (1.0 - alpha) * ewma;

	return ewma;
}


/* Input arrays must be in chronological order (oldest first) */
static double aggregate_diff_percentage(
	double *counters, int count, double *base_counters)
{
	double total_increment = 0.0;
	double total_base = 0.0;
	int i;

	if (count <= 1)
		return 0.0;

	for (i = 1; i < count; i++) {
		double increment;
		double base_increment;

		if (counters[i] >= counters[i - 1]) {
			increment = counters[i] - counters[i - 1];
		} else {
			increment = counters[i];
			wpa_printf(MSG_DEBUG,
				   "wifi_stats: Counter rollover detected at index %d (%.0f -> %.0f)",
				   i, counters[i - 1], counters[i]);
		}

		if (base_counters[i] >= base_counters[i - 1]) {
			base_increment = base_counters[i] - base_counters[i - 1];
		} else {
			base_increment = base_counters[i];
		}

		total_increment += increment;
		total_base += base_increment;
	}

	if (total_base > 0.0)
		return (total_increment / total_base) * 100.0;

	return 0.0;
}


static double apply_aggregation(wifi_stats_agg_type_t type, double *data,
				int count, unsigned int weight)
{
	switch (type) {
	case WIFI_STATS_AGG_AVG_LIN:
		return aggregate_avg_linear(data, count);
	case WIFI_STATS_AGG_MAX:
		return aggregate_max(data, count);
	case WIFI_STATS_AGG_MIN:
		return aggregate_min(data, count);
	case WIFI_STATS_AGG_AVG_EXP:
		return aggregate_avg_exponential(data, count, weight);
	case WIFI_STATS_AGG_ACC:
	case WIFI_STATS_AGG_NONE:
	case WIFI_STATS_AGG_COUNT:
		break;
	}
	return 0.0;
}


static void generate_timeframe_string_from_time(char *buffer, size_t buffer_len,
						const struct os_time *timestamps,
						int point_count)
{
	long sec_diff;
	int usec_diff;
	int total_seconds;
	int minutes;

	if (point_count < 2 || !timestamps) {
		os_snprintf(buffer, buffer_len, "1S");
		return;
	}

	/* Compute span rounded to nearest second; avoids microsecond
	 * multiplication that overflows 32-bit long at >2147s */
	sec_diff = timestamps[point_count - 1].sec - timestamps[0].sec;
	usec_diff = timestamps[point_count - 1].usec - timestamps[0].usec;
	if (usec_diff < 0) {
		sec_diff--;
		usec_diff += 1000000;
	}
	total_seconds = (int)sec_diff + (usec_diff >= 500000 ? 1 : 0);

	if (total_seconds < 1)
		total_seconds = 1;

	/* Spec ABNF limits WINDOW to 3 digits; switch to minutes above 999s */
	if (total_seconds <= 999) {
		os_snprintf(buffer, buffer_len, "%dS", total_seconds);
	} else {
		minutes = (total_seconds + 30) / 60;
		if (minutes > 999)
			minutes = 999;
		os_snprintf(buffer, buffer_len, "%dM", minutes);
	}
}


static double extract_station_metric(const struct hostap_sta_driver_data *data,
				     wifi_stats_metric_type_t metric)
{
	switch (metric) {
	case WIFI_STATS_METRIC_RX_BITRATE:
		return (double)data->current_rx_rate;
	case WIFI_STATS_METRIC_TX_BITRATE:
		return (double)data->current_tx_rate;
	case WIFI_STATS_METRIC_RSSI:
		return (double)data->signal;
	case WIFI_STATS_METRIC_FRAME_RETRY:
		return (double)data->tx_retry_count;
	case WIFI_STATS_METRIC_FRAME_LOSS:
		return (double)data->tx_retry_failed;
	case WIFI_STATS_METRIC_COUNT:
		break;
	}
	return 0.0;
}


static const char *wifi_stats_detect_protocol(struct hostapd_data *hapd,
					      struct sta_info *sta,
					      const struct hostap_sta_driver_data *sta_data)
{
	int freq;

	if (sta) {
		if (sta->flags & WLAN_STA_EHT)
			return "802.11be";
		if (sta->flags & WLAN_STA_HE)
			return "802.11ax";
		if ((sta->flags & WLAN_STA_VHT) ||
		    (sta_data->flags & (STA_DRV_DATA_TX_VHT_MCS | STA_DRV_DATA_RX_VHT_MCS)))
			return "802.11ac";
		if ((sta->flags & WLAN_STA_HT) ||
		    (sta_data->flags & (STA_DRV_DATA_TX_MCS | STA_DRV_DATA_RX_MCS)))
			return "802.11n";

		if (hapd->iconf &&
		    hapd->iconf->hw_mode == HOSTAPD_MODE_IEEE80211B)
			return "802.11b";

		freq = hapd->iface ? hapd->iface->freq : 0;
		return freq >= 5000 ? "802.11a" : "802.11g";
	}

	if (hapd->iconf) {
		if (hapd->iconf->ieee80211be)
			return "802.11be";
		if (hapd->iconf->ieee80211ax)
			return "802.11ax";
		if (hapd->iconf->ieee80211ac)
			return "802.11ac";
		if (hapd->iconf->ieee80211n)
			return "802.11n";
		if (hapd->iconf->hw_mode == HOSTAPD_MODE_IEEE80211A)
			return "802.11a";
		if (hapd->iconf->hw_mode == HOSTAPD_MODE_IEEE80211G)
			return "802.11g";
		if (hapd->iconf->hw_mode == HOSTAPD_MODE_IEEE80211B)
			return "802.11b";
	}

	return "802.11b";
}


static int wifi_stats_get_channel_width(struct hostapd_config *conf)
{
	if (!conf)
		return 20;

	if (conf->ieee80211be || conf->ieee80211ax || conf->ieee80211ac) {
		switch (hostapd_get_oper_chwidth(conf)) {
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
			break;
		}
	}

	if (conf->ieee80211n && conf->secondary_channel)
		return 40;

	return 20;
}


static int wifi_stats_get_max_bitrate_1ss_tenths(const char *protocol,
						 int channel_width)
{
	if (os_strcmp(protocol, "802.11be") == 0) {
		if (channel_width >= 320)
			return 28824;
		if (channel_width >= 160)
			return 14412;
		if (channel_width >= 80)
			return 7206;
		if (channel_width >= 40)
			return 3441;
		return 1721;
	}
	if (os_strcmp(protocol, "802.11ax") == 0) {
		if (channel_width >= 160)
			return 12010;
		if (channel_width >= 80)
			return 6004;
		if (channel_width >= 40)
			return 2868;
		return 1434;
	}
	if (os_strcmp(protocol, "802.11ac") == 0) {
		if (channel_width >= 160)
			return 8667;
		if (channel_width >= 80)
			return 4333;
		if (channel_width >= 40)
			return 2000;
		return 867;
	}
	if (os_strcmp(protocol, "802.11n") == 0) {
		if (channel_width >= 40)
			return 1500;
		return 722;
	}
	if (os_strcmp(protocol, "802.11b") == 0)
		return 110;

	return 540;
}


static int wifi_stats_nss_from_mcs_map(u16 map)
{
	int i, nss = 0;

	for (i = 0; i < 8; i++) {
		if (((map >> (i * 2)) & 0x3) != 0x3)
			nss = i + 1;
	}

	return nss;
}


static int wifi_stats_nss_from_ht_mcs_set(const u8 *mcs_set)
{
	int i, nss = 0;

	for (i = 0; i < 4; i++) {
		if (mcs_set[i])
			nss = i + 1;
	}

	return nss;
}


static int wifi_stats_get_sta_capab_nss(struct sta_info *sta)
{
	int nss, i;

	if (!sta)
		return 0;

	if (sta->he_capab &&
	    sta->he_capab_len >= IEEE80211_HE_CAPAB_MIN_LEN + 2) {
		nss = wifi_stats_nss_from_mcs_map(le_to_host16(
			sta->he_capab->he_basic_supported_mcs_set.rx_map));
		if (nss > 0)
			return nss;
	}

	if (sta->vht_capabilities) {
		u16 tx_map = le_to_host16(
			sta->vht_capabilities->vht_supported_mcs_set.tx_map);

		nss = 1;
		for (i = 1; i < 8; i++) {
			if (((tx_map >> (i * 2)) & 0x3) != 0x3)
				nss = i + 1;
		}
		return nss;
	}

	if (sta->ht_capabilities) {
		nss = wifi_stats_nss_from_ht_mcs_set(
			sta->ht_capabilities->supported_mcs_set);
		if (nss > 0)
			return nss;
	}

	return 0;
}


static int wifi_stats_get_ap_nss(struct hostapd_data *hapd)
{
	struct hostapd_hw_modes *mode;
	const struct he_capabilities *he;
	u16 map;
	int nss;

	if (!hapd->iface || !hapd->iface->current_mode)
		return 0;
	mode = hapd->iface->current_mode;

	he = &mode->he_capab[IEEE80211_MODE_AP];
	if (he->he_supported) {
		map = WPA_GET_LE16(&he->mcs[2]);
		if (map) {
			nss = wifi_stats_nss_from_mcs_map(map);
			if (nss > 0)
				return nss;
		}
	}

	map = WPA_GET_LE16(&mode->vht_mcs_set[4]);
	if (map) {
		nss = wifi_stats_nss_from_mcs_map(map);
		if (nss > 0)
			return nss;
	}

	return wifi_stats_nss_from_ht_mcs_set(mode->mcs_set);
}


static int wifi_stats_get_station_nss(struct hostapd_data *hapd,
				      struct sta_info *sta,
				      const struct hostap_sta_driver_data *sta_data)
{
	int nss, ap_nss;

	nss = wifi_stats_get_sta_capab_nss(sta);
	if (nss > 0) {
		ap_nss = wifi_stats_get_ap_nss(hapd);
		if (ap_nss > 0 && ap_nss < nss)
			nss = ap_nss;
		return nss;
	}

	if ((sta_data->flags & STA_DRV_DATA_TX_HE_NSS) &&
	    sta_data->tx_he_nss > 0)
		return sta_data->tx_he_nss;

	if ((sta_data->flags & STA_DRV_DATA_TX_VHT_NSS) && sta_data->tx_vht_nss > 0)
		return sta_data->tx_vht_nss;

	if (sta_data->flags & STA_DRV_DATA_TX_MCS) {
		if (sta_data->tx_mcs < 32)
			return (sta_data->tx_mcs / 8) + 1;
		return 1;
	}

	return 1;
}


/*
 * Reset semantics differ per algorithm. MIN/MAX/AVG-LIN discard their state.
 * ACC must carry the current counter pair forward as the new baseline.
 * AVG-EXP keeps its filter state entirely
 */
static void wifi_stats_accum_reset(struct wifi_stats_accum *acc)
{
	double ewma = acc->ewma;
	int ewma_valid = acc->ewma_valid;
	double last_val = acc->last_val;
	double last_base = acc->last_base;
	struct os_time last_ts = acc->last_ts;

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
				       const struct os_time *now)
{
	int metric;

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++)
		wifi_stats_accum_reset(&sb->accum[metric]);
	sb->period_start = *now;
}


static void wifi_stats_accum_update(struct wifi_stats_accum *acc,
				    double value, double base,
				    const struct os_time *now,
				    unsigned int ewma_weight)
{
	double alpha;

	if (acc->count == 0) {
		acc->min = value;
		acc->max = value;
		acc->sum = value;
		acc->first_ts = *now;
		if (acc->last_ts.sec == 0 && acc->last_ts.usec == 0) {
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
		alpha = 1.0 / (double)(1u << ewma_weight);
		acc->ewma += alpha * (value - acc->ewma);
	}

	if ((acc->count > 0 || acc->last_ts.sec != 0 || acc->last_ts.usec != 0) &&
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


static double wifi_stats_metric_base(const struct hostap_sta_driver_data *data,
				     wifi_stats_metric_type_t metric)
{
	switch (metric) {
	case WIFI_STATS_METRIC_FRAME_LOSS:
		return (double)data->tx_packets;
	case WIFI_STATS_METRIC_FRAME_RETRY:
		return (double)(data->tx_packets + data->tx_retry_count);
	case WIFI_STATS_METRIC_RX_BITRATE:
	case WIFI_STATS_METRIC_TX_BITRATE:
	case WIFI_STATS_METRIC_RSSI:
	case WIFI_STATS_METRIC_COUNT:
		break;
	}
	return 0.0;
}


static void wifi_stats_accum_collect(struct wifi_stats_ctx *ctx,
				     struct wifi_stats_sta_buf *sb,
				     const struct hostap_sta_driver_data *data,
				     const struct os_time *now)
{
	int metric;

	if (sb->period_start.sec &&
	    now->sec - sb->period_start.sec > (long)ctx->window_seconds)
		wifi_stats_accum_reset_all(sb, now);
	else if (!sb->period_start.sec)
		sb->period_start = *now;

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
		if (ctx->agg_config[metric] == WIFI_STATS_AGG_NONE)
			continue;
		wifi_stats_accum_update(&sb->accum[metric],
					extract_station_metric(data, metric),
					wifi_stats_metric_base(data, metric),
					now, ctx->ewma_weight);
	}
}


static double wifi_stats_accum_value(const struct wifi_stats_accum *acc,
				     wifi_stats_agg_type_t algorithm)
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


static void wifi_stats_aggregate_accum(struct wifi_stats_ctx *ctx,
				       struct wifi_stats_sta_buf *sta_buf,
				       struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT])
{
	int metric;

	os_memset(results, 0,
		  sizeof(struct wifi_stats_agg_result) * WIFI_STATS_METRIC_COUNT);

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
		wifi_stats_agg_type_t config = ctx->agg_config[metric];
		struct wifi_stats_accum *acc = &sta_buf->accum[metric];
		struct os_time span[2];
		int is_acc = config == WIFI_STATS_AGG_ACC;
		int rebased = is_acc &&
			(acc->base_ts.sec != acc->first_ts.sec ||
			 acc->base_ts.usec != acc->first_ts.usec);

		results[metric].algorithm = config;

		if (config == WIFI_STATS_AGG_NONE)
			continue;

		results[metric].actual_points = (int)acc->count +
						 (rebased ? 1 : 0);
		results[metric].value = wifi_stats_accum_value(acc, config);

		span[0] = is_acc ? acc->base_ts : acc->first_ts;
		span[1] = acc->last_ts;
		generate_timeframe_string_from_time(
			results[metric].timeframe_str,
			sizeof(results[metric].timeframe_str),
			span, results[metric].actual_points > 1 ? 2 : 0);

		if (results[metric].actual_points > 0) {
			wpa_printf(MSG_DEBUG, "wifi_stats: " MACSTR " %s: %.1f (%s %s, %d points)",
				   MAC2STR(sta_buf->addr),
				   wifi_stats_metric_type_to_str(metric),
				   results[metric].value,
				   wifi_stats_agg_type_to_str(
					   results[metric].algorithm),
				   results[metric].timeframe_str,
				   results[metric].actual_points);
		}
	}
}


static int wifi_stats_aggregate_for_station(struct wifi_stats_ctx *ctx,
					    struct wifi_stats_sta_buf *sta_buf,
					    struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT])
{
	size_t buf_max;
	struct os_time now;
	double *data_points;
	struct os_time *timestamps;
	double *base_counters;
	int metric;

	if (!ctx || !sta_buf || !results)
		return -1;

	if (ctx->span_mode == WIFI_STATS_SPAN_REPORT) {
		wifi_stats_aggregate_accum(ctx, sta_buf, results);
		return 0;
	}

	os_memset(results, 0,
		  sizeof(struct wifi_stats_agg_result) * WIFI_STATS_METRIC_COUNT);

	if (wifi_stats_all_metrics_none(ctx) || ctx->aggregation_suppressed) {
		for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++)
			results[metric].algorithm = WIFI_STATS_AGG_NONE;
		return 0;
	}

	buf_max = sta_buf->buf.max_len;
	if (buf_max == 0)
		return 0;

	os_get_time(&now);

	data_points = os_malloc(buf_max * (2 * sizeof(double) +
			        sizeof(struct os_time)));
	if (!data_points) {
		wpa_printf(MSG_ERROR, "wifi_stats: Failed to allocate aggregation buffer");
		return -1;
	}
	base_counters = data_points + buf_max;
	timestamps = (struct os_time *)(base_counters + buf_max);

	for (metric = 0; metric < WIFI_STATS_METRIC_COUNT; metric++) {
		wifi_stats_agg_type_t config = ctx->agg_config[metric];
		int point_count = 0;
		unsigned int window_sec = ctx->window_seconds;
		int available_entries = (int)sta_buf->buf.count;
		int need_base_counter = (config == WIFI_STATS_AGG_ACC);
		int i;

		if (config == WIFI_STATS_AGG_NONE) {
			results[metric].algorithm = WIFI_STATS_AGG_NONE;
			continue;
		}

		/* Walk oldest-to-newest, skip stale entries, fill from first
		 * in-window entry onward - already in chronological order */
		for (i = 0; i < available_entries; i++) {
			size_t idx = (sta_buf->buf.head - available_entries + i +
				      sta_buf->buf.max_len) %
				     sta_buf->buf.max_len;
			struct wifi_stats_sample *entry =
				wifi_stats_circular_get(&sta_buf->buf, idx);
			long age_sec;

			if (!entry)
				break;
			age_sec = now.sec - entry->timestamp.sec;
			if (age_sec < 0)
				age_sec = 0;
			if ((unsigned int)age_sec > window_sec)
				continue;

			data_points[point_count] = extract_station_metric(
				&entry->data, metric);
			timestamps[point_count] = entry->timestamp;

			if (need_base_counter)
				base_counters[point_count] =
					wifi_stats_metric_base(&entry->data,
							       metric);

			point_count++;
		}

		results[metric].algorithm = config;
		results[metric].actual_points = point_count;

		if (point_count > 0) {
			if (need_base_counter)
				results[metric].value =
					aggregate_diff_percentage(data_points,
								  point_count,
								  base_counters);
			else
				results[metric].value =
					apply_aggregation(config, data_points,
							  point_count,
							  ctx->ewma_weight);
		} else {
			results[metric].value = 0.0;
		}

		generate_timeframe_string_from_time(results[metric].timeframe_str,
						    sizeof(results[metric].timeframe_str),
						    timestamps, point_count);

		if (point_count > 0) {
			wpa_printf(MSG_DEBUG, "wifi_stats: " MACSTR " %s: %.1f (%s %s, %d points)",
				   MAC2STR(sta_buf->addr),
				   wifi_stats_metric_type_to_str(metric),
				   results[metric].value,
				   wifi_stats_agg_type_to_str(
					   results[metric].algorithm),
				   results[metric].timeframe_str, point_count);
		}
	}

	os_free(data_points);

	return 0;
}


static void wifi_stats_timer_cb(void *eloop_ctx, void *timeout_ctx);

static void wifi_stats_stop_timer(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->timer_active) {
		wpa_printf(MSG_DEBUG, "wifi_stats: Stopping collection timer");
		eloop_cancel_timeout(wifi_stats_timer_cb, ctx, NULL);
		ctx->timer_active = 0;
	}

	ctx->iface = NULL;
}


struct wifi_stats_ctx *wifi_stats_init(void)
{
	struct wifi_stats_ctx *ctx;
	int i;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->collection_interval = WIFI_STATS_DEFAULT_INTERVAL;
	ctx->window_seconds = WIFI_STATS_DEFAULT_WINDOW;
	ctx->ewma_weight = WIFI_STATS_DEFAULT_EWMA_WEIGHT;
	ctx->span_mode = WIFI_STATS_SPAN_REPORT;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
		ctx->agg_config[i] = wifi_stats_default_algorithm(i);

	return ctx;
}


void wifi_stats_deinit(struct wifi_stats_ctx *ctx)
{
	struct hostapd_iface *iface;

	if (!ctx)
		return;

	iface = ctx->iface;
	wifi_stats_stop_timer(ctx);

	while (ctx->sta_bufs)
		wifi_stats_unlink_and_free_buf(&ctx->sta_bufs, iface);

	os_free(ctx);
}


void wifi_stats_mark_signalled(struct wifi_stats_ctx *ctx, const u8 *addr)
{
	struct wifi_stats_sta_buf *sb;
	struct os_time now;

	if (!ctx || !addr || ctx->span_mode != WIFI_STATS_SPAN_REPORT)
		return;

	sb = wifi_stats_find_sta_buf(ctx, addr);
	if (!sb)
		return;

	os_get_time(&now);
	wifi_stats_accum_reset_all(sb, &now);
	wpa_printf(MSG_DEBUG, "wifi_stats: Reset aggregation for " MACSTR
		   " after accounting report", MAC2STR(addr));
}


void wifi_stats_forget_sta(struct wifi_stats_ctx *ctx, const u8 *addr)
{
	struct wifi_stats_sta_buf *sb, **pp;

	if (!ctx || !addr)
		return;

	pp = &ctx->sta_bufs;
	while (*pp) {
		sb = *pp;
		if (os_memcmp(sb->addr, addr, ETH_ALEN) == 0) {
			wpa_printf(MSG_DEBUG,
				   "wifi_stats: Forgot buffer for " MACSTR,
				   MAC2STR(addr));
			wifi_stats_unlink_and_free_buf(pp, ctx->iface);
			return;
		}
		pp = &sb->next;
	}
}


static void wifi_stats_collect(struct wifi_stats_ctx *ctx,
			       struct hostapd_iface *iface)
{
	struct os_time now;
	size_t bss_idx;

	if (!ctx || !iface)
		return;

	if (wifi_stats_all_metrics_none(ctx))
		return;

	os_get_time(&now);

	for (bss_idx = 0; bss_idx < iface->num_bss; bss_idx++) {
		struct hostapd_data *bss = iface->bss[bss_idx];
		struct sta_info *sta;

		for (sta = bss->sta_list; sta; sta = sta->next) {
			struct wifi_stats_sta_buf *sb;
			struct hostap_sta_driver_data sta_data;
			struct wifi_stats_sample sample;

			if (!(sta->flags & WLAN_STA_ASSOC))
				continue;

			if (!sta->wifi_stats) {
				sb = wifi_stats_find_sta_buf(ctx, sta->addr);
				if (!sb)
					sb = wifi_stats_sta_buf_alloc(ctx,
								      sta->addr);
				if (!sb)
					continue;
				sta->wifi_stats = sb;
			}

			os_memset(&sta_data, 0, sizeof(sta_data));
			if (hostapd_drv_read_sta_data(bss, &sta_data,
						      sta->addr) != 0) {
				wpa_printf(MSG_DEBUG,
					   "wifi_stats: Failed to read sta data for " MACSTR,
					   MAC2STR(sta->addr));
				continue;
			}

			sb = sta->wifi_stats;
			os_memcpy(&sb->last_data, &sta_data,
				  sizeof(sta_data));
			sb->last_data_valid = 1;
			sb->last_update = now;

			if (ctx->span_mode == WIFI_STATS_SPAN_REPORT) {
				wifi_stats_accum_collect(ctx, sb, &sta_data,
							 &now);
				continue;
			}

			os_memcpy(&sample.data, &sta_data,
				  sizeof(sta_data));
			sample.timestamp = now;
			wifi_stats_circular_push(&sb->buf, &sample);
		}
	}

	wifi_stats_prune_stale_bufs(ctx, iface);
}


static void wifi_stats_timer_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct wifi_stats_ctx *ctx = eloop_ctx;

	if (!ctx || !ctx->iface)
		return;

	wifi_stats_collect(ctx, ctx->iface);

	if (ctx->timer_active &&
	    eloop_register_timeout(ctx->collection_interval, 0,
				   wifi_stats_timer_cb, ctx, NULL) < 0) {
		wpa_printf(MSG_WARNING,
			   "wifi_stats: Failed to reschedule collection timer, stopping collection");
		ctx->timer_active = 0;
	}
}


int wifi_stats_start_timer(struct wifi_stats_ctx *ctx,
			   struct hostapd_iface *iface)
{
	if (!ctx || !iface)
		return -1;

	wifi_stats_stop_timer(ctx);

	ctx->iface = iface;
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
 * AVG-EXP reports the exponential weight rather than a time span, per
 * draft-grayson-connectinfo-10
 * AGGR = ALGO SP ( WINDOW / (WEIGHT ["-" SAMPLE]) ).
 * SAMPLE is not emitted: it is the collection interval in milliseconds, which
 * is at least 1000 while the field is limited to three digits.
 */
static const char * wifi_stats_aggr_suffix(struct wifi_stats_ctx *ctx,
					   const struct wifi_stats_agg_result *res,
					   char *buf, size_t buf_len)
{
	if (res->algorithm == WIFI_STATS_AGG_AVG_EXP) {
		os_snprintf(buf, buf_len, "%u", ctx->ewma_weight);
		return buf;
	}
	return res->timeframe_str;
}


static int wifi_stats_get_global_op_class(struct hostapd_data *hapd)
{
	const char *country;
	u8 op_class = 0, channel = 0;
	int freq;

	if (!hapd || !hapd->iconf)
		return 0;

	country = hapd->iconf->country[0] ? hapd->iconf->country : NULL;

	if (hapd->iconf->op_class)
		return country_to_global_op_class(country,
						  hapd->iconf->op_class);

	freq = hapd->iface ? hapd->iface->freq : 0;
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
	return (int)(value < 0 ? value - 0.5 : value + 0.5);
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
	if (mbps > 9999.9)
		return 9999.9;
	return mbps;
}


static double wifi_stats_clamp_maxspeed(double mbps)
{
	if (mbps < 0.0)
		return 0.0;
	if (mbps > 99999.99)
		return 99999.99;
	return mbps;
}

static int wifi_stats_emit_bitrate(char **pos, char *end,
				   wifi_stats_metric_type_t metric,
				   const struct wifi_stats_agg_result *result,
				   const struct hostap_sta_driver_data *data,
				   struct wifi_stats_ctx *ctx)
{
	char aggr_buf[8];
	int written = 0;
	int aggregated = result->actual_points > 1;
	double mbps = wifi_stats_clamp_rate(
		(aggregated ? result->value :
		 extract_station_metric(data, metric)) / 1000.0);

	if (mbps >= 0.05) {
		if (aggregated)
			written = os_snprintf(*pos, end - *pos,
					      " %s:%.1f(%s %s)",
					      metric_names[metric], mbps,
					      wifi_stats_agg_type_to_str(result->algorithm),
					      wifi_stats_aggr_suffix(ctx, result, aggr_buf,
								     sizeof(aggr_buf)));
		else
			written = os_snprintf(*pos, end - *pos, " %s:%.1f",
					      metric_names[metric], mbps);
	}
	if (written && os_snprintf_error(end - *pos, written))
		return -1;
	*pos += written;
	return 0;
}


static int wifi_stats_emit_rssi(char **pos, char *end,
				const struct wifi_stats_agg_result *result,
				const struct hostap_sta_driver_data *data,
				struct wifi_stats_ctx *ctx)
{
	char aggr_buf[8];
	int written = 0;
	int aggregated = result->actual_points > 1;
	int dbm = wifi_stats_clamp_rssi(
		aggregated ? wifi_stats_round_nearest(result->value) :
		data->signal);

	if (dbm != 0) {
		if (aggregated)
			written = os_snprintf(*pos, end - *pos,
					      " RSSI:%d(%s %s)", dbm,
					      wifi_stats_agg_type_to_str(result->algorithm),
					      wifi_stats_aggr_suffix(ctx, result, aggr_buf,
								     sizeof(aggr_buf)));
		else
			written = os_snprintf(*pos, end - *pos, " RSSI:%d",
					      dbm);
	}
	if (written && os_snprintf_error(end - *pos, written))
		return -1;
	*pos += written;
	return 0;
}


static int wifi_stats_emit_pct(char **pos, char *end,
			       wifi_stats_metric_type_t metric,
			       const struct wifi_stats_agg_result *result,
			       const struct hostap_sta_driver_data *data,
			       struct wifi_stats_ctx *ctx)
{
	char aggr_buf[8];
	int written;
	double instant_numerator = extract_station_metric(data, metric);
	double instant_denominator = wifi_stats_metric_base(data, metric);

	if (result->actual_points > 1) {
		written = os_snprintf(*pos, end - *pos, " %s:%d(%s %s)",
				      metric_names[metric],
				      wifi_stats_clamp_pct(result->value),
				      wifi_stats_agg_type_to_str(result->algorithm),
				      wifi_stats_aggr_suffix(ctx, result, aggr_buf,
							     sizeof(aggr_buf)));
	} else if (result->algorithm == WIFI_STATS_AGG_NONE &&
		   instant_denominator > 0) {
		written = os_snprintf(*pos, end - *pos, " %s:%d",
				      metric_names[metric],
				      wifi_stats_clamp_pct(
					      instant_numerator * 100 /
					      instant_denominator));
	} else {
		written = 0;
	}
	if (written && os_snprintf_error(end - *pos, written))
		return -1;
	*pos += written;
	return 0;
}


int wifi_stats_format_connection_info(struct wifi_stats_ctx *ctx,
				      struct hostapd_data *hapd,
				      struct sta_info *sta,
				      const u8 *sta_addr,
				      char *buffer,
				      size_t buffer_len)
{
	struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT];
	struct wifi_stats_agg_result *rssi, *tx, *rx, *loss, *retry;
	struct hostap_sta_driver_data sta_data;
	struct wifi_stats_sta_buf *sta_buf;
	struct os_time now;
	const char *protocol;
	char *pos, *end;
	int written, channel_width, nss, max_bitrate_tenths, freq;
	int global_op_class;
	u8 channel_num = 0;

	if (!ctx || !hapd || !sta_addr || !buffer || buffer_len == 0)
		return -1;

	sta_buf = sta ? sta->wifi_stats : NULL;
	if (!sta_buf)
		sta_buf = wifi_stats_find_sta_buf(ctx, sta_addr);

	if (sta_buf) {
		if (wifi_stats_aggregate_for_station(ctx, sta_buf,
						     results) != 0)
			return -1;
	} else {
		int i;

		os_memset(results, 0, sizeof(results));
		for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
			results[i].algorithm = ctx->agg_config[i];
	}

	pos = buffer;
	end = buffer + buffer_len;

	os_memset(&sta_data, 0, sizeof(sta_data));
	os_get_time(&now);

	if (sta_buf && sta_buf->last_data_valid &&
	    now.sec - sta_buf->last_update.sec <=
	    2 * (long)ctx->collection_interval) {
		os_memcpy(&sta_data, &sta_buf->last_data, sizeof(sta_data));
	} else if (hostapd_drv_read_sta_data(hapd, &sta_data,
					     sta_addr) != 0) {
		return -1;
	}

	protocol = wifi_stats_detect_protocol(hapd, sta, &sta_data);
	channel_width = wifi_stats_get_channel_width(hapd->iconf);
	nss = wifi_stats_get_station_nss(hapd, sta, &sta_data);
	max_bitrate_tenths = wifi_stats_get_max_bitrate_1ss_tenths(
		protocol, channel_width) * nss;

	freq = hapd->iface ? hapd->iface->freq : 0;
	if (freq)
		ieee80211_freq_to_chan(freq, &channel_num);

	written = os_snprintf(pos, end - pos, "CONNECT %.2f Mbps %s",
			      wifi_stats_clamp_maxspeed(max_bitrate_tenths /
							10.0),
			      protocol);
	if (os_snprintf_error(end - pos, written))
		return -1;
	pos += written;

	if (channel_num > 0) {
		written = os_snprintf(pos, end - pos, " Channel:%d",
				      (int)channel_num);
		if (os_snprintf_error(end - pos, written))
			return -1;
		pos += written;
	}

	rssi = &results[WIFI_STATS_METRIC_RSSI];
	if (wifi_stats_emit_rssi(&pos, end, rssi, &sta_data, ctx))
		return -1;

	/* Driver bitrate fields are in kbps; convert to Mbps */
	tx = &results[WIFI_STATS_METRIC_TX_BITRATE];
	if (wifi_stats_emit_bitrate(&pos, end, WIFI_STATS_METRIC_TX_BITRATE, tx,
				    &sta_data, ctx))
		return -1;

	rx = &results[WIFI_STATS_METRIC_RX_BITRATE];
	if (wifi_stats_emit_bitrate(&pos, end, WIFI_STATS_METRIC_RX_BITRATE, rx,
				    &sta_data, ctx))
		return -1;

	loss = &results[WIFI_STATS_METRIC_FRAME_LOSS];
	if (wifi_stats_emit_pct(&pos, end, WIFI_STATS_METRIC_FRAME_LOSS, loss,
				&sta_data, ctx))
		return -1;

	retry = &results[WIFI_STATS_METRIC_FRAME_RETRY];
	if (wifi_stats_emit_pct(&pos, end, WIFI_STATS_METRIC_FRAME_RETRY, retry,
				&sta_data, ctx))
		return -1;

	global_op_class = wifi_stats_get_global_op_class(hapd);
	if (global_op_class > 0 && global_op_class <= 255) {
		written = os_snprintf(pos, end - pos, " Global-OC:%d",
				      global_op_class);
		if (os_snprintf_error(end - pos, written))
			return -1;
		pos += written;
	}

	return (int)(pos - buffer);
}


int wifi_stats_set_interval(struct wifi_stats_ctx *ctx, unsigned int interval)
{
	if (!ctx)
		return -1;
	return wifi_stats_set_params(ctx, interval, ctx->window_seconds);
}


unsigned int wifi_stats_get_interval(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return 0;
	return ctx->collection_interval;
}


int wifi_stats_set_params(struct wifi_stats_ctx *ctx, unsigned int interval,
			  unsigned int window)
{
	int interval_changed;
	int ret = 0;

	if (!ctx)
		return -1;

	if (interval < WIFI_STATS_MIN_INTERVAL || interval > WIFI_STATS_MAX_INTERVAL)
		return -1;
	if (window < WIFI_STATS_MIN_WINDOW || window > WIFI_STATS_MAX_WINDOW)
		return -1;

	interval_changed = interval != ctx->collection_interval;

	ctx->collection_interval = interval;
	ctx->window_seconds = window;
	wifi_stats_check_degenerate_config(ctx);
	wifi_stats_resize_all_bufs(ctx);

	if (interval_changed && ctx->timer_active && ctx->iface &&
	    wifi_stats_start_timer(ctx, ctx->iface) < 0)
		ret = -1;

	wpa_printf(MSG_DEBUG, "wifi_stats: Set interval=%us window=%us",
		   ctx->collection_interval, ctx->window_seconds);

	return ret;
}


int wifi_stats_set_window(struct wifi_stats_ctx *ctx, unsigned int window)
{
	if (!ctx)
		return -1;
	return wifi_stats_set_params(ctx, ctx->collection_interval, window);
}


unsigned int wifi_stats_get_window(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return 0;
	return ctx->window_seconds;
}


int wifi_stats_set_metric_config(struct wifi_stats_ctx *ctx,
				 wifi_stats_metric_type_t metric,
				 wifi_stats_agg_type_t algorithm)
{
	int was_all_none, is_all_none;

	if (!ctx || metric >= WIFI_STATS_METRIC_COUNT ||
	    algorithm >= WIFI_STATS_AGG_COUNT)
		return -1;

	if (algorithm != WIFI_STATS_AGG_NONE) {
		if (algorithm == WIFI_STATS_AGG_ACC &&
		    metric != WIFI_STATS_METRIC_FRAME_LOSS &&
		    metric != WIFI_STATS_METRIC_FRAME_RETRY) {
			wpa_printf(MSG_ERROR,
				   "wifi_stats: ACC algorithm only valid for FrameLoss/FrameRetry");
			return -1;
		}
		if (algorithm != WIFI_STATS_AGG_ACC &&
		    (metric == WIFI_STATS_METRIC_FRAME_LOSS ||
		     metric == WIFI_STATS_METRIC_FRAME_RETRY)) {
			wpa_printf(MSG_ERROR,
				   "wifi_stats: FrameLoss/FrameRetry require ACC or NONE algorithm");
			return -1;
		}
	}

	was_all_none = wifi_stats_all_metrics_none(ctx);
	ctx->agg_config[metric] = algorithm;
	is_all_none = wifi_stats_all_metrics_none(ctx);

	if (was_all_none != is_all_none)
		wifi_stats_resize_all_bufs(ctx);

	wpa_printf(MSG_DEBUG, "wifi_stats: Set metric %s=%s",
		   wifi_stats_metric_type_to_str(metric),
		   wifi_stats_agg_type_to_str(algorithm));

	return 0;
}


wifi_stats_agg_type_t wifi_stats_get_metric_config(struct wifi_stats_ctx *ctx,
						   wifi_stats_metric_type_t metric)
{
	if (!ctx || metric >= WIFI_STATS_METRIC_COUNT)
		return WIFI_STATS_AGG_COUNT;
	return ctx->agg_config[metric];
}


static const char *span_mode_strings[WIFI_STATS_SPAN_COUNT] = {
	[WIFI_STATS_SPAN_REPORT] = "report",
	[WIFI_STATS_SPAN_WINDOW] = "window"
};


const char * wifi_stats_span_mode_to_str(wifi_stats_span_mode_t mode)
{
	if (mode < WIFI_STATS_SPAN_COUNT)
		return span_mode_strings[mode];
	return "UNKNOWN";
}


wifi_stats_span_mode_t wifi_stats_span_mode_from_str(const char *str)
{
	int i;

	if (!str)
		return WIFI_STATS_SPAN_COUNT;
	for (i = 0; i < WIFI_STATS_SPAN_COUNT; i++) {
		if (os_strcmp(str, span_mode_strings[i]) == 0)
			return (wifi_stats_span_mode_t)i;
	}
	return WIFI_STATS_SPAN_COUNT;
}


int wifi_stats_set_span_mode(struct wifi_stats_ctx *ctx,
			     wifi_stats_span_mode_t mode)
{
	struct wifi_stats_sta_buf *sb;

	if (!ctx || mode >= WIFI_STATS_SPAN_COUNT)
		return -1;
	if (ctx->span_mode == mode)
		return 0;

	ctx->span_mode = mode;
	wifi_stats_check_degenerate_config(ctx);
	/* Buffers are only needed for the sliding window */
	wifi_stats_resize_all_bufs(ctx);

	for (sb = ctx->sta_bufs; sb; sb = sb->next) {
		os_memset(&sb->accum, 0, sizeof(sb->accum));
		os_memset(&sb->period_start, 0, sizeof(sb->period_start));
	}

	wpa_printf(MSG_DEBUG, "wifi_stats: Set span=%s",
		   wifi_stats_span_mode_to_str(mode));
	return 0;
}


wifi_stats_span_mode_t wifi_stats_get_span_mode(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return WIFI_STATS_SPAN_COUNT;
	return ctx->span_mode;
}


int wifi_stats_set_ewma_weight(struct wifi_stats_ctx *ctx, unsigned int weight)
{
	if (!ctx)
		return -1;
	if (weight < WIFI_STATS_MIN_EWMA_WEIGHT ||
	    weight > WIFI_STATS_MAX_EWMA_WEIGHT)
		return -1;

	ctx->ewma_weight = weight;
	wpa_printf(MSG_DEBUG, "wifi_stats: Set ewma_weight=%u (alpha=1/%u)",
		   weight, 1u << weight);
	return 0;
}


unsigned int wifi_stats_get_ewma_weight(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return WIFI_STATS_DEFAULT_EWMA_WEIGHT;
	return ctx->ewma_weight;
}


const char * wifi_stats_agg_type_to_str(wifi_stats_agg_type_t type)
{
	if (type < WIFI_STATS_AGG_COUNT)
		return agg_type_strings[type];
	return "UNKNOWN";
}


const char * wifi_stats_metric_type_to_str(wifi_stats_metric_type_t metric)
{
	if (metric < WIFI_STATS_METRIC_COUNT)
		return metric_names[metric];
	return "UNKNOWN";
}


wifi_stats_agg_type_t wifi_stats_agg_type_from_str(const char *str)
{
	int i;

	if (!str)
		return WIFI_STATS_AGG_COUNT;
	for (i = 0; i < WIFI_STATS_AGG_COUNT; i++) {
		if (os_strcasecmp(str, agg_type_strings[i]) == 0)
			return (wifi_stats_agg_type_t)i;
	}
	return WIFI_STATS_AGG_COUNT;
}


wifi_stats_metric_type_t wifi_stats_metric_type_from_str(const char *str)
{
	int i;

	if (!str)
		return WIFI_STATS_METRIC_COUNT;
	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (os_strcasecmp(str, metric_names[i]) == 0)
			return (wifi_stats_metric_type_t)i;
	}
	return WIFI_STATS_METRIC_COUNT;
}
