/*
 * wifi_stats.h - Periodic WiFi statistics collection for hostapd
 *
 * This module provides logic to periodically collect per-station statistics
 * from the driver and format Connect-Info attributes.
 */

#ifndef WIFI_STATS_H
#define WIFI_STATS_H

#define WIFI_STATS_DEFAULT_INTERVAL 1
#define WIFI_STATS_WBA_DEFAULT_WINDOW 60
#define WIFI_STATS_MAX_CONN_INFO_LEN 253

typedef enum {
	WIFI_STATS_AGG_MIN,
	WIFI_STATS_AGG_MAX,
	WIFI_STATS_AGG_AVG,
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

struct wifi_stats_agg_config {
	wifi_stats_agg_type_t algorithm;
};

struct wifi_stats_agg_result {
	double value;
	wifi_stats_agg_type_t algorithm;
	int actual_points;
	char timeframe_str[16];
};

struct hostapd_data;
struct hostapd_iface;
struct sta_info;
struct wifi_stats_ctx;
struct wifi_stats_sta_buf;

struct wifi_stats_ctx *wifi_stats_init(unsigned int interval,
				      unsigned int default_window);
void wifi_stats_deinit(struct wifi_stats_ctx *ctx);
int wifi_stats_start_timer(struct wifi_stats_ctx *ctx,
			   struct hostapd_iface *iface);
void wifi_stats_stop_timer(struct wifi_stats_ctx *ctx);
int wifi_stats_set_interval(struct wifi_stats_ctx *ctx, unsigned int interval);
unsigned int wifi_stats_get_interval(struct wifi_stats_ctx *ctx);
int wifi_stats_format_connection_info(struct wifi_stats_ctx *ctx,
				      struct hostapd_data *hapd,
				      struct sta_info *sta,
				      const u8 *sta_addr,
				      char *buffer,
				      size_t buffer_len);
int wifi_stats_set_metric_config(struct wifi_stats_ctx *ctx,
				 wifi_stats_metric_type_t metric,
				 wifi_stats_agg_type_t algorithm);
wifi_stats_agg_type_t wifi_stats_get_metric_config(struct wifi_stats_ctx *ctx,
						   wifi_stats_metric_type_t metric);
int wifi_stats_set_window(struct wifi_stats_ctx *ctx, unsigned int window);
unsigned int wifi_stats_get_window(struct wifi_stats_ctx *ctx);
const char *wifi_stats_agg_type_to_str(wifi_stats_agg_type_t type);
const char *wifi_stats_metric_type_to_str(wifi_stats_metric_type_t metric);
wifi_stats_agg_type_t wifi_stats_agg_type_from_str(const char *str);
wifi_stats_metric_type_t wifi_stats_metric_type_from_str(const char *str);
wifi_stats_metric_type_t wifi_stats_metric_type_from_config_str(const char *str);

#endif /* WIFI_STATS_H */
