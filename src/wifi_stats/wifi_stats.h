/*
 * wifi_stats.h - Periodic WiFi statistics collection for hostapd
 * Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
 *
 * This module provides logic to periodically collect per-station statistics
 * from the driver and format Connect-Info attributes.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WIFI_STATS_H
#define WIFI_STATS_H

#define WIFI_STATS_DEFAULT_INTERVAL 1
#define WIFI_STATS_MIN_INTERVAL 1
#define WIFI_STATS_MAX_INTERVAL 3600
#define WIFI_STATS_DEFAULT_WINDOW 60
#define WIFI_STATS_MIN_WINDOW 1
#define WIFI_STATS_MAX_WINDOW 3600
#define WIFI_STATS_MAX_CONN_INFO_LEN 253
#define WIFI_STATS_DEFAULT_EWMA_WEIGHT 5
#define WIFI_STATS_MIN_EWMA_WEIGHT 1
#define WIFI_STATS_MAX_EWMA_WEIGHT 9

/*
 * How the aggregation span is determined. REPORT accumulates incrementally
 * and resets when an accounting report is sent, as described in
 * draft-grayson-connectinfo-10 Section 4.2. WINDOW keeps a sliding window of
 * samples covering the configured number of seconds.
 */
typedef enum {
	WIFI_STATS_SPAN_REPORT,
	WIFI_STATS_SPAN_WINDOW,
	WIFI_STATS_SPAN_COUNT
} wifi_stats_span_mode_t;

typedef enum {
	WIFI_STATS_AGG_MIN,
	WIFI_STATS_AGG_MAX,
	WIFI_STATS_AGG_AVG_LIN,
	WIFI_STATS_AGG_AVG_EXP,
	WIFI_STATS_AGG_ACC,
	WIFI_STATS_AGG_NONE,
	WIFI_STATS_AGG_COUNT
} wifi_stats_agg_type_t;

typedef enum {
	WIFI_STATS_METRIC_RX_BITRATE,
	WIFI_STATS_METRIC_TX_BITRATE,
	WIFI_STATS_METRIC_RSSI,
	WIFI_STATS_METRIC_FRAME_LOSS,
	WIFI_STATS_METRIC_FRAME_RETRY,
	WIFI_STATS_METRIC_COUNT
} wifi_stats_metric_type_t;

struct hostapd_data;
struct hostapd_iface;
struct sta_info;
struct wifi_stats_ctx;

struct wifi_stats_ctx *wifi_stats_init(void);
void wifi_stats_deinit(struct wifi_stats_ctx *ctx);
int wifi_stats_start_timer(struct wifi_stats_ctx *ctx,
			   struct hostapd_iface *iface);

int wifi_stats_set_interval(struct wifi_stats_ctx *ctx, unsigned int interval);
unsigned int wifi_stats_get_interval(struct wifi_stats_ctx *ctx);
int wifi_stats_set_window(struct wifi_stats_ctx *ctx, unsigned int window);
unsigned int wifi_stats_get_window(struct wifi_stats_ctx *ctx);
int wifi_stats_set_params(struct wifi_stats_ctx *ctx, unsigned int interval,
			  unsigned int window);
int wifi_stats_set_metric_config(struct wifi_stats_ctx *ctx,
				 wifi_stats_metric_type_t metric,
				 wifi_stats_agg_type_t algorithm);
wifi_stats_agg_type_t wifi_stats_get_metric_config(struct wifi_stats_ctx *ctx,
						   wifi_stats_metric_type_t metric);
wifi_stats_agg_type_t wifi_stats_default_algorithm(
	wifi_stats_metric_type_t metric);
int wifi_stats_set_span_mode(struct wifi_stats_ctx *ctx,
			     wifi_stats_span_mode_t mode);
wifi_stats_span_mode_t wifi_stats_get_span_mode(struct wifi_stats_ctx *ctx);
int wifi_stats_set_ewma_weight(struct wifi_stats_ctx *ctx, unsigned int weight);
unsigned int wifi_stats_get_ewma_weight(struct wifi_stats_ctx *ctx);
void wifi_stats_mark_signalled(struct wifi_stats_ctx *ctx, const u8 *addr);
void wifi_stats_forget_sta(struct wifi_stats_ctx *ctx, const u8 *addr);
int wifi_stats_format_connection_info(struct wifi_stats_ctx *ctx,
				      struct hostapd_data *hapd,
				      struct sta_info *sta,
				      const u8 *sta_addr,
				      char *buffer,
				      size_t buffer_len);

const char * wifi_stats_span_mode_to_str(wifi_stats_span_mode_t mode);
wifi_stats_span_mode_t wifi_stats_span_mode_from_str(const char *str);
const char * wifi_stats_agg_type_to_str(wifi_stats_agg_type_t type);
wifi_stats_agg_type_t wifi_stats_agg_type_from_str(const char *str);
const char * wifi_stats_metric_type_to_str(wifi_stats_metric_type_t metric);
wifi_stats_metric_type_t wifi_stats_metric_type_from_str(const char *str);

#endif /* WIFI_STATS_H */
