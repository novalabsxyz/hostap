/*
 * wifi_stats.c - Periodic WiFi statistics collection for hostapd
 *
 * This module provides logic to periodically collect per-station statistics
 * from the driver, store them in per-station circular buffers, and format
 * Connect-Info attributes with aggregated metrics per draft-grayson-connectinfo-07.
 */

#include "includes.h"
#include "common.h"
#include "os.h"
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

struct wifi_stats_sta_buf {
	u8 addr[ETH_ALEN];
	struct wifi_stats_circular buf;
	struct wifi_stats_sta_buf *next;
};

struct wifi_stats_ctx {
	unsigned int collection_interval;
	unsigned int window_seconds;
	struct hostapd_iface *iface;
	int timer_active;
	struct wifi_stats_agg_config agg_config[WIFI_STATS_METRIC_COUNT];
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
	if (!buf->entries)
		return -1;

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

	if (!ctx)
		return 1;
	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (ctx->agg_config[i].algorithm != WIFI_STATS_AGG_NONE)
			return 0;
	}
	return 1;
}

static void wifi_stats_force_all_none(struct wifi_stats_ctx *ctx)
{
	int i;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
		ctx->agg_config[i].algorithm = WIFI_STATS_AGG_NONE;
}

static void wifi_stats_check_degenerate_config(struct wifi_stats_ctx *ctx)
{
	if (ctx->window_seconds <= ctx->collection_interval) {
		wifi_stats_force_all_none(ctx);
		wpa_printf(MSG_INFO,
			   "wifi_stats: window (%us) <= interval (%us), forcing all metrics to NONE",
			   ctx->window_seconds, ctx->collection_interval);
	}
}

static size_t wifi_stats_compute_buf_max(struct wifi_stats_ctx *ctx)
{
	if (wifi_stats_all_metrics_none(ctx))
		return 0;
	if (ctx->collection_interval == 0)
		return 0;
	return ctx->window_seconds / ctx->collection_interval + 1;
}

static struct wifi_stats_sta_buf *wifi_stats_find_sta_buf(struct wifi_stats_ctx *ctx,
							  const u8 *addr)
{
	struct wifi_stats_sta_buf *sb;

	for (sb = ctx->sta_bufs; sb; sb = sb->next) {
		if (os_memcmp(sb->addr, addr, ETH_ALEN) == 0)
			return sb;
	}
	return NULL;
}

static struct wifi_stats_sta_buf *wifi_stats_sta_buf_alloc(struct wifi_stats_ctx *ctx,
							   const u8 *addr)
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

	if (!iface)
		return;
	for (j = 0; j < iface->num_bss; j++) {
		for (sta = iface->bss[j]->sta_list; sta; sta = sta->next) {
			if (sta->wifi_stats == sb)
				sta->wifi_stats = NULL;
		}
	}
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

		if (sb->buf.count == 0) {
			*pp = sb->next;
			wifi_stats_clear_sta_refs(iface, sb);
			wifi_stats_circular_free(&sb->buf);
			os_free(sb);
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
			*pp = sb->next;
			wifi_stats_clear_sta_refs(iface, sb);
			wifi_stats_circular_free(&sb->buf);
			os_free(sb);
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

/* Algorithm defaults per draft-grayson-connectinfo-07 Section 2 */
static const wifi_stats_agg_type_t default_algorithms[WIFI_STATS_METRIC_COUNT] = {
	[WIFI_STATS_METRIC_RX_BITRATE] = WIFI_STATS_AGG_MAX,
	[WIFI_STATS_METRIC_TX_BITRATE] = WIFI_STATS_AGG_MAX,
	[WIFI_STATS_METRIC_RSSI] = WIFI_STATS_AGG_AVG_LIN,
	[WIFI_STATS_METRIC_FRAME_LOSS] = WIFI_STATS_AGG_ACC,
	[WIFI_STATS_METRIC_FRAME_RETRY] = WIFI_STATS_AGG_ACC
};

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
	[WIFI_STATS_AGG_AVG] = "AVG",
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

static double aggregate_avg_exponential(double *data, int count)
{
	double alpha;
	double ewma;
	int i;

	if (count <= 0)
		return 0.0;
	if (count == 1)
		return data[0];

	alpha = 2.0 / (count + 1);
	ewma = data[0];
	for (i = 1; i < count; i++)
		ewma = alpha * data[i] + (1.0 - alpha) * ewma;

	return ewma;
}

/* Input arrays must be in chronological order (oldest first) */
static double aggregate_diff_percentage(double *counters, int count, double *base_counters)
{
	double total_increment = 0.0;
	double total_base = 0.0;
	int i;

	if (count <= 1)
		return 0.0;

	for (i = 1; i < count; i++) {
		double increment;
		double base_increment;

		if (counters[i] >= counters[i-1]) {
			increment = counters[i] - counters[i-1];
		} else {
			increment = counters[i];
			wpa_printf(MSG_DEBUG, "wifi_stats: Counter rollover detected at index %d (%.0f -> %.0f)",
				   i, counters[i-1], counters[i]);
		}

		if (base_counters[i] >= base_counters[i-1]) {
			base_increment = base_counters[i] - base_counters[i-1];
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

static double apply_aggregation(wifi_stats_agg_type_t type, double *data, int count)
{
	switch (type) {
	case WIFI_STATS_AGG_AVG_LIN:
	case WIFI_STATS_AGG_AVG:
		return aggregate_avg_linear(data, count);
	case WIFI_STATS_AGG_MAX:
		return aggregate_max(data, count);
	case WIFI_STATS_AGG_MIN:
		return aggregate_min(data, count);
	case WIFI_STATS_AGG_AVG_EXP:
		return aggregate_avg_exponential(data, count);
	default:
		return 0.0;
	}
}

static void generate_timeframe_string_from_time(char *buffer, size_t buffer_len,
						const struct os_time *timestamps,
						int point_count)
{
	long sec_diff;
	int usec_diff;
	int total_seconds;

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
	if (total_seconds <= 999)
		os_snprintf(buffer, buffer_len, "%dS", total_seconds);
	else
		os_snprintf(buffer, buffer_len, "%dM",
			    (total_seconds + 30) / 60);
	buffer[buffer_len - 1] = '\0';
}

static double extract_station_metric(struct wifi_stats_sample *entry, wifi_stats_metric_type_t metric)
{
	switch (metric) {
	case WIFI_STATS_METRIC_RX_BITRATE:
		return (double)entry->data.current_rx_rate;
	case WIFI_STATS_METRIC_TX_BITRATE:
		return (double)entry->data.current_tx_rate;
	case WIFI_STATS_METRIC_RSSI:
		return (double)entry->data.signal;
	case WIFI_STATS_METRIC_FRAME_RETRY:
		return (double)entry->data.tx_retry_count;
	case WIFI_STATS_METRIC_FRAME_LOSS:
		return (double)entry->data.tx_retry_failed;
	default:
		return 0.0;
	}
}

static const char *wifi_stats_detect_protocol(struct hostapd_data *hapd,
					      struct sta_info *sta,
					      const struct hostap_sta_driver_data *sta_data)
{
	int freq;

	if (sta) {
#ifdef CONFIG_IEEE80211BE
		if (sta->flags & WLAN_STA_EHT)
			return "802.11be";
#endif /* CONFIG_IEEE80211BE */
		if (sta->flags & WLAN_STA_HE)
			return "802.11ax";
		if ((sta->flags & WLAN_STA_VHT) ||
		    (sta_data->flags & (STA_DRV_DATA_TX_VHT_MCS | STA_DRV_DATA_RX_VHT_MCS)))
			return "802.11ac";
		if ((sta->flags & WLAN_STA_HT) ||
		    (sta_data->flags & (STA_DRV_DATA_TX_MCS | STA_DRV_DATA_RX_MCS)))
			return "802.11n";

		freq = hapd->iface ? hapd->iface->freq : 0;
		return freq >= 5000 ? "802.11a" : "802.11g";
	}

	if (hapd->iconf) {
#ifdef CONFIG_IEEE80211BE
		if (hapd->iconf->ieee80211be)
			return "802.11be";
#endif /* CONFIG_IEEE80211BE */
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

	/* TODO: EHT/320MHz once eht_oper_chwidth lands in ap_config */

	if (conf->ieee80211ac || conf->ieee80211ax) {
		switch (conf->vht_oper_chwidth) {
		case CHANWIDTH_80MHZ:
		case CHANWIDTH_80P80MHZ:
			return 80;
		case CHANWIDTH_160MHZ:
			return 160;
		default:
			return conf->secondary_channel ? 40 : 20;
		}
	}

	if (conf->ieee80211n && conf->secondary_channel)
		return 40;

	return 20;
}

/* 1SS max rates per protocol/bandwidth per SC * MD * CR * SS / (SYM + GD) */
static int wifi_stats_get_max_bitrate_1ss(const char *protocol, int channel_width)
{
	if (os_strcmp(protocol, "802.11be") == 0) {
		if (channel_width >= 320) return 11530;
		if (channel_width >= 160) return 5765;
		if (channel_width >= 80) return 2882;
		if (channel_width >= 40) return 1441;
		return 720;
	}
	if (os_strcmp(protocol, "802.11ax") == 0) {
		if (channel_width >= 160) return 1201;
		if (channel_width >= 80) return 601;
		if (channel_width >= 40) return 287;
		return 143;
	}
	if (os_strcmp(protocol, "802.11ac") == 0) {
		if (channel_width >= 160) return 867;
		if (channel_width >= 80) return 433;
		if (channel_width >= 40) return 200;
		return 87;
	}
	if (os_strcmp(protocol, "802.11n") == 0) {
		if (channel_width >= 40) return 150;
		return 72;
	}
	if (os_strcmp(protocol, "802.11b") == 0)
		return 11;

	return 54;
}

static int wifi_stats_get_station_nss(struct sta_info *sta,
				      const struct hostap_sta_driver_data *sta_data)
{
	if ((sta_data->flags & STA_DRV_DATA_TX_VHT_NSS) && sta_data->tx_vht_nss > 0)
		return sta_data->tx_vht_nss;

	if (sta_data->flags & STA_DRV_DATA_TX_MCS)
		return (sta_data->tx_mcs / 8) + 1;

	if (sta && sta->vht_capabilities) {
		u16 tx_map = le_to_host16(
			sta->vht_capabilities->vht_supported_mcs_set.tx_map);
		int nss = 1;
		int i;
		for (i = 1; i < 8; i++) {
			if (((tx_map >> (i * 2)) & 0x3) != 0x3)
				nss = i + 1;
		}
		return nss;
	}

	return 1;
}

static int wifi_stats_aggregate_for_station(struct wifi_stats_ctx *ctx,
					    struct wifi_stats_sta_buf *sta_buf,
					    const u8 *sta_addr,
					    struct wifi_stats_agg_result results[WIFI_STATS_METRIC_COUNT])
{
	size_t buf_max;
	struct os_time now;
	double *data_points;
	struct os_time *timestamps;
	double *base_counters;
	int metric;

	if (!ctx || !sta_buf || !sta_addr || !results)
		return -1;

	os_memset(results, 0, sizeof(struct wifi_stats_agg_result) * WIFI_STATS_METRIC_COUNT);

	if (wifi_stats_all_metrics_none(ctx)) {
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
		struct wifi_stats_agg_config *config = &ctx->agg_config[metric];
		int point_count = 0;
		unsigned int window_sec = ctx->window_seconds;
		int available_entries = (int)sta_buf->buf.count;
		int need_base_counter = (config->algorithm == WIFI_STATS_AGG_ACC);
		int i;

		if (config->algorithm == WIFI_STATS_AGG_NONE) {
			results[metric].algorithm = WIFI_STATS_AGG_NONE;
			results[metric].actual_points = 0;
			results[metric].value = 0.0;
			continue;
		}

		/* Walk oldest-to-newest, skip stale entries, fill from first
		 * in-window entry onward — already in chronological order */
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
				entry, metric);
			timestamps[point_count] = entry->timestamp;

			if (need_base_counter) {
				/* FrameLoss base = tx_packets (MSDUs to driver),
				 * FrameRetry base = tx_packets + retries (on-air MPDUs) */
				if (metric == WIFI_STATS_METRIC_FRAME_LOSS)
					base_counters[point_count] =
						(double)entry->data.tx_packets;
				else
					base_counters[point_count] =
						(double)(entry->data.tx_packets +
							 entry->data.tx_retry_count);
			}

			point_count++;
		}

		results[metric].algorithm = config->algorithm;
		results[metric].actual_points = point_count;

		if (point_count > 0) {
			if (need_base_counter)
				results[metric].value = aggregate_diff_percentage(data_points, point_count, base_counters);
			else
				results[metric].value = apply_aggregation(config->algorithm, data_points, point_count);
		} else {
			results[metric].value = 0.0;
		}

		generate_timeframe_string_from_time(results[metric].timeframe_str,
						    sizeof(results[metric].timeframe_str),
						    timestamps, point_count);

		if (point_count > 0) {
			wpa_printf(MSG_DEBUG, "wifi_stats: " MACSTR " %s: %.1f (%s-%s, %d points)",
				   MAC2STR(sta_addr), metric_names[metric],
				   results[metric].value,
				   agg_type_strings[results[metric].algorithm],
				   results[metric].timeframe_str, point_count);
		}
	}

	os_free(data_points);

	return 0;
}

static void wifi_stats_timer_cb(void *eloop_ctx, void *timeout_ctx);

void wifi_stats_stop_timer(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->timer_active) {
		wpa_printf(MSG_INFO, "wifi_stats: Stopping collection timer");
		eloop_cancel_timeout(wifi_stats_timer_cb, ctx, NULL);
		ctx->timer_active = 0;
	}

	ctx->iface = NULL;
}

struct wifi_stats_ctx *wifi_stats_init(unsigned int interval,
				      unsigned int default_window)
{
	struct wifi_stats_ctx *ctx;
	int i;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (interval == 0 || interval > 3600)
		interval = WIFI_STATS_DEFAULT_INTERVAL;
	ctx->collection_interval = interval;
	if (default_window < 1 || default_window > 3600)
		default_window = WIFI_STATS_WBA_DEFAULT_WINDOW;
	ctx->window_seconds = default_window;
	ctx->sta_bufs = NULL;

	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
		ctx->agg_config[i].algorithm = default_algorithms[i];

	wifi_stats_check_degenerate_config(ctx);

	wpa_printf(MSG_DEBUG, "wifi_stats: interval=%us window=%us",
		   ctx->collection_interval, ctx->window_seconds);

	return ctx;
}

void wifi_stats_deinit(struct wifi_stats_ctx *ctx)
{
	struct wifi_stats_sta_buf *sb, *next;

	if (!ctx)
		return;
	wifi_stats_stop_timer(ctx);

	for (sb = ctx->sta_bufs; sb; sb = next) {
		next = sb->next;
		wifi_stats_circular_free(&sb->buf);
		os_free(sb);
	}
	ctx->sta_bufs = NULL;

	os_free(ctx);
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

			os_memset(&sample, 0, sizeof(sample));
			os_memcpy(&sample.data, &sta_data,
				  sizeof(sta_data));
			sample.timestamp = now;
			wifi_stats_circular_push(
				&sta->wifi_stats->buf, &sample);
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

	if (ctx->timer_active) {
		eloop_register_timeout(ctx->collection_interval, 0,
				       wifi_stats_timer_cb, ctx, NULL);
	}
}

int wifi_stats_start_timer(struct wifi_stats_ctx *ctx, struct hostapd_iface *iface)
{
	if (!ctx || !iface)
		return -1;

	wifi_stats_stop_timer(ctx);

	ctx->iface = iface;
	ctx->timer_active = 1;

	wpa_printf(MSG_INFO, "wifi_stats: Starting collection timer (interval: %u seconds)",
		   ctx->collection_interval);

	eloop_register_timeout(ctx->collection_interval, 0,
			       wifi_stats_timer_cb, ctx, NULL);

	return 0;
}

int wifi_stats_set_interval(struct wifi_stats_ctx *ctx, unsigned int interval)
{
	if (!ctx)
		return -1;

	if (interval == 0 || interval > 3600)
		return -1;

	ctx->collection_interval = interval;
	wifi_stats_check_degenerate_config(ctx);
	wifi_stats_resize_all_bufs(ctx);

	if (ctx->timer_active && ctx->iface) {
		eloop_cancel_timeout(wifi_stats_timer_cb, ctx, NULL);
		eloop_register_timeout(ctx->collection_interval, 0,
				       wifi_stats_timer_cb, ctx, NULL);
		wpa_printf(MSG_INFO, "wifi_stats: Restarted timer (interval=%us)",
			   ctx->collection_interval);
	}

	return 0;
}

unsigned int wifi_stats_get_interval(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return 0;
	return ctx->collection_interval;
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
	const char *protocol;
	char *pos;
	size_t remaining;
	int written, channel_width, nss, max_bitrate_mbps, freq;
	u8 channel_num = 0;

	if (!ctx || !hapd || !sta_addr || !buffer || buffer_len == 0)
		return -1;

	sta_buf = sta ? sta->wifi_stats : NULL;
	if (!sta_buf)
		sta_buf = wifi_stats_find_sta_buf(ctx, sta_addr);

	/*
	 * Only connection-specific metrics go here; non-connection metrics
	 * (ChanUtil, Noise, STA_cnt) go into separate WBA VSAs.
	 */
	if (sta_buf) {
		if (wifi_stats_aggregate_for_station(ctx, sta_buf, sta_addr,
						     results) != 0)
			return -1;
	} else {
		int i;

		os_memset(results, 0, sizeof(results));
		for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++)
			results[i].algorithm = ctx->agg_config[i].algorithm;
	}

	pos = buffer;
	remaining = buffer_len;

	/* Reuse latest buffered sample; only query the driver when empty */
	os_memset(&sta_data, 0, sizeof(sta_data));
	if (sta_buf && sta_buf->buf.count > 0) {
		size_t newest_idx = (sta_buf->buf.head - 1 +
				     sta_buf->buf.max_len) %
				    sta_buf->buf.max_len;
		struct wifi_stats_sample *newest =
			wifi_stats_circular_get(&sta_buf->buf, newest_idx);
		if (newest)
			os_memcpy(&sta_data, &newest->data, sizeof(sta_data));
	} else if (hostapd_drv_read_sta_data(hapd, &sta_data,
					     sta_addr) != 0) {
		return -1;
	}

	protocol = wifi_stats_detect_protocol(hapd, sta, &sta_data);
	channel_width = wifi_stats_get_channel_width(hapd->iconf);
	nss = wifi_stats_get_station_nss(sta, &sta_data);
	max_bitrate_mbps = wifi_stats_get_max_bitrate_1ss(protocol, channel_width) * nss;

	freq = hapd->iface ? hapd->iface->freq : 0;
	if (freq)
		ieee80211_freq_to_chan(freq, &channel_num);

	written = os_snprintf(pos, remaining, "CONNECT %.2fMbps %s",
			      (double)max_bitrate_mbps, protocol);
	if (written < 0 || (size_t)written >= remaining)
		return -1;
	pos += written;
	remaining -= written;

	if (channel_num > 0) {
		written = os_snprintf(pos, remaining, " Channel:%d",
				      (int)channel_num);
		if (written < 0 || (size_t)written >= remaining)
			return -1;
		pos += written;
		remaining -= written;
	}

	rssi = &results[WIFI_STATS_METRIC_RSSI];
	if (rssi->actual_points > 1) {
		written = os_snprintf(pos, remaining, " RSSI:%d(%s %s)",
				      (int)rssi->value,
				      agg_type_strings[rssi->algorithm],
				      rssi->timeframe_str);
	} else {
		written = os_snprintf(pos, remaining, " RSSI:%d",
				      (int)sta_data.signal);
	}
	if (written < 0 || (size_t)written >= remaining)
		return -1;
	pos += written;
	remaining -= written;

	/* Aggregated bitrate is in 100 kbps units; convert to Mbps */
	tx = &results[WIFI_STATS_METRIC_TX_BITRATE];
	if (tx->actual_points > 1) {
		written = os_snprintf(pos, remaining, " TxBitRate:%.1f(%s %s)",
				      tx->value / 10.0,
				      agg_type_strings[tx->algorithm],
				      tx->timeframe_str);
	} else if (sta_data.current_tx_rate > 0) {
		written = os_snprintf(pos, remaining, " TxBitRate:%.1f",
				      (double)sta_data.current_tx_rate / 10.0);
	} else {
		written = 0;
	}
	if (written < 0 || (size_t)written >= remaining)
		return -1;
	pos += written;
	remaining -= written;

	rx = &results[WIFI_STATS_METRIC_RX_BITRATE];
	if (rx->actual_points > 1) {
		written = os_snprintf(pos, remaining, " RxBitRate:%.1f(%s %s)",
				      rx->value / 10.0,
				      agg_type_strings[rx->algorithm],
				      rx->timeframe_str);
	} else if (sta_data.current_rx_rate > 0) {
		written = os_snprintf(pos, remaining, " RxBitRate:%.1f",
				      (double)sta_data.current_rx_rate / 10.0);
	} else {
		written = 0;
	}
	if (written < 0 || (size_t)written >= remaining)
		return -1;
	pos += written;
	remaining -= written;

	loss = &results[WIFI_STATS_METRIC_FRAME_LOSS];
	if (loss->actual_points > 1) {
		written = os_snprintf(pos, remaining, " FrameLoss:%d(%s %s)",
				      (int)loss->value,
				      agg_type_strings[loss->algorithm],
				      loss->timeframe_str);
		if (written < 0 || (size_t)written >= remaining)
			return -1;
		pos += written;
		remaining -= written;
	} else if (loss->algorithm == WIFI_STATS_AGG_NONE &&
		   sta_data.tx_packets > 0) {
		written = os_snprintf(pos, remaining, " FrameLoss:%d",
				      (int)((unsigned long long)sta_data.tx_retry_failed * 100 /
					    sta_data.tx_packets));
		if (written < 0 || (size_t)written >= remaining)
			return -1;
		pos += written;
		remaining -= written;
	}

	retry = &results[WIFI_STATS_METRIC_FRAME_RETRY];
	if (retry->actual_points > 1) {
		written = os_snprintf(pos, remaining, " FrameRetry:%d(%s %s)",
				      (int)retry->value,
				      agg_type_strings[retry->algorithm],
				      retry->timeframe_str);
		if (written < 0 || (size_t)written >= remaining)
			return -1;
		pos += written;
		remaining -= written;
	} else if (retry->algorithm == WIFI_STATS_AGG_NONE &&
		   (sta_data.tx_packets + sta_data.tx_retry_count) > 0) {
		written = os_snprintf(pos, remaining, " FrameRetry:%d",
				      (int)((unsigned long long)sta_data.tx_retry_count * 100 /
					    (sta_data.tx_packets + sta_data.tx_retry_count)));
		if (written < 0 || (size_t)written >= remaining)
			return -1;
		pos += written;
		remaining -= written;
	}

	return (int)(pos - buffer);
}

int wifi_stats_set_metric_config(struct wifi_stats_ctx *ctx,
				 wifi_stats_metric_type_t metric,
				 wifi_stats_agg_type_t algorithm)
{
	int was_all_none, is_all_none;

	if (!ctx || metric >= WIFI_STATS_METRIC_COUNT || algorithm >= WIFI_STATS_AGG_COUNT)
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
	ctx->agg_config[metric].algorithm = algorithm;
	is_all_none = wifi_stats_all_metrics_none(ctx);

	if (was_all_none != is_all_none)
		wifi_stats_resize_all_bufs(ctx);

	return 0;
}

wifi_stats_agg_type_t wifi_stats_get_metric_config(struct wifi_stats_ctx *ctx,
						   wifi_stats_metric_type_t metric)
{
	if (!ctx || metric >= WIFI_STATS_METRIC_COUNT)
		return WIFI_STATS_AGG_AVG;
	return ctx->agg_config[metric].algorithm;
}

int wifi_stats_set_window(struct wifi_stats_ctx *ctx, unsigned int window)
{
	if (!ctx)
		return -1;
	if (window < 1 || window > 3600)
		return -1;

	ctx->window_seconds = window;
	wifi_stats_check_degenerate_config(ctx);
	wifi_stats_resize_all_bufs(ctx);

	wpa_printf(MSG_INFO, "wifi_stats: Set window=%us",
		   ctx->window_seconds);
	return 0;
}

unsigned int wifi_stats_get_window(struct wifi_stats_ctx *ctx)
{
	if (!ctx)
		return 0;
	return ctx->window_seconds;
}

const char *wifi_stats_agg_type_to_str(wifi_stats_agg_type_t type)
{
	if (type < WIFI_STATS_AGG_COUNT)
		return agg_type_strings[type];
	return "UNKNOWN";
}

const char *wifi_stats_metric_type_to_str(wifi_stats_metric_type_t metric)
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
		if (os_strcmp(str, agg_type_strings[i]) == 0)
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
		if (os_strcmp(str, metric_names[i]) == 0)
			return (wifi_stats_metric_type_t)i;
	}
	return WIFI_STATS_METRIC_COUNT;
}

static const char *metric_config_names[WIFI_STATS_METRIC_COUNT] = {
	[WIFI_STATS_METRIC_RX_BITRATE] = "rxbitrate",
	[WIFI_STATS_METRIC_TX_BITRATE] = "txbitrate",
	[WIFI_STATS_METRIC_RSSI] = "rssi",
	[WIFI_STATS_METRIC_FRAME_LOSS] = "frameloss",
	[WIFI_STATS_METRIC_FRAME_RETRY] = "frameretry"
};

wifi_stats_metric_type_t wifi_stats_metric_type_from_config_str(const char *str)
{
	int i;

	if (!str)
		return WIFI_STATS_METRIC_COUNT;
	for (i = 0; i < WIFI_STATS_METRIC_COUNT; i++) {
		if (os_strcmp(str, metric_config_names[i]) == 0)
			return (wifi_stats_metric_type_t)i;
	}
	return WIFI_STATS_METRIC_COUNT;
}
