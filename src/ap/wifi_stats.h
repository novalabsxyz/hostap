/*
 * Periodic Wi-Fi statistics collection for hostapd
 * Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WIFI_STATS_H
#define WIFI_STATS_H

#define WIFI_STATS_DEFAULT_INTERVAL 1 /* seconds */
#define WIFI_STATS_MIN_INTERVAL 1 /* seconds */
#define WIFI_STATS_MAX_INTERVAL 3600 /* seconds */
#define WIFI_STATS_DEFAULT_WINDOW 60 /* seconds */
#define WIFI_STATS_MIN_WINDOW 1 /* seconds */
#define WIFI_STATS_MAX_WINDOW 3600 /* seconds */
#define WIFI_STATS_MAX_CONNECT_INFO_LEN 253
#define WIFI_STATS_DEFAULT_EWMA_WEIGHT 5
#define WIFI_STATS_MIN_EWMA_WEIGHT 1
#define WIFI_STATS_MAX_EWMA_WEIGHT 9

/*
 * How the aggregation span is determined. WINDOW, the default, keeps a sliding
 * window of samples covering the configured number of seconds: the WINDOW of
 * the draft-ietf-radext-connectinfo-02 ABNF, "the time window over which the
 * algorithm operates". REPORT accumulates incrementally and resets when an
 * accounting report is sent, as described in Section 4.2 of the draft.
 */
enum wifi_stats_span_mode {
	WIFI_STATS_SPAN_REPORT,
	WIFI_STATS_SPAN_WINDOW,
	WIFI_STATS_SPAN_COUNT
};

enum wifi_stats_agg_type {
	WIFI_STATS_AGG_MIN,
	WIFI_STATS_AGG_MAX,
	WIFI_STATS_AGG_AVG_LIN,
	WIFI_STATS_AGG_AVG_EXP,
	WIFI_STATS_AGG_ACC,
	WIFI_STATS_AGG_NONE,
	WIFI_STATS_AGG_COUNT
};

enum wifi_stats_metric_type {
	WIFI_STATS_METRIC_RX_BITRATE,
	WIFI_STATS_METRIC_TX_BITRATE,
	WIFI_STATS_METRIC_RSSI,
	WIFI_STATS_METRIC_FRAME_LOSS,
	WIFI_STATS_METRIC_FRAME_RETRY,
	WIFI_STATS_METRIC_COUNT
};

struct hostapd_data;
struct hostapd_iface;
struct sta_info;
struct wifi_stats_ctx;

#ifdef CONFIG_WIFI_STATS

void wifi_stats_init(struct hostapd_iface *iface);
void wifi_stats_deinit(struct hostapd_iface *iface);
void wifi_stats_reload_config(struct hostapd_iface *iface);
void wifi_stats_new_assoc(struct hostapd_data *hapd, struct sta_info *sta);
void wifi_stats_free_sta(struct hostapd_data *hapd, struct sta_info *sta);
void wifi_stats_mark_signalled(struct hostapd_data *hapd,
			       struct sta_info *sta);
int wifi_stats_connect_info(struct hostapd_data *hapd, struct sta_info *sta,
			    char *buf, size_t buflen);
int wifi_stats_get_status(struct hostapd_iface *iface, char *buf,
			  size_t buflen);

bool wifi_stats_algorithm_valid(enum wifi_stats_metric_type metric,
				enum wifi_stats_agg_type algorithm);
enum wifi_stats_span_mode wifi_stats_span_mode_from_str(const char *str);
enum wifi_stats_agg_type wifi_stats_agg_type_from_str(const char *str);
enum wifi_stats_metric_type wifi_stats_metric_type_from_str(const char *str);

#else /* CONFIG_WIFI_STATS */

static inline void wifi_stats_init(struct hostapd_iface *iface)
{
}

static inline void wifi_stats_deinit(struct hostapd_iface *iface)
{
}

static inline void wifi_stats_reload_config(struct hostapd_iface *iface)
{
}

static inline void wifi_stats_new_assoc(struct hostapd_data *hapd,
					struct sta_info *sta)
{
}

static inline void wifi_stats_free_sta(struct hostapd_data *hapd,
				       struct sta_info *sta)
{
}

static inline void wifi_stats_mark_signalled(struct hostapd_data *hapd,
					     struct sta_info *sta)
{
}

static inline int wifi_stats_connect_info(struct hostapd_data *hapd,
					  struct sta_info *sta, char *buf,
					  size_t buflen)
{
	return -1;
}

#endif /* CONFIG_WIFI_STATS */

#endif /* WIFI_STATS_H */
