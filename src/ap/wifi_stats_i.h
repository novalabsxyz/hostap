/*
 * Wi-Fi statistics - Internal definitions
 * Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WIFI_STATS_I_H
#define WIFI_STATS_I_H

#include "wifi_stats.h"

/*
 * What aggregation reads of a driver snapshot. In a window and in an
 * accumulator it has been through wifi_stats_drop_stale(): a signal or rate of
 * 0 is one that was not fresh.
 */
struct wifi_stats_sample {
	struct os_reltime timestamp;
	unsigned long tx_packets;
	unsigned long tx_retry_count;
	unsigned long tx_retry_failed;
	unsigned long current_tx_rate;
	unsigned long current_rx_rate;
	int signal;
};

/*
 * Incremental per-metric state: every algorithm is a streaming statistic, so
 * no sample history is needed. Both spans keep one per station and metric,
 * which a window reads its AVG-EXP filter from; a window also folds the
 * samples it holds into one on the stack for the other algorithms.
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
	struct os_reltime first_ts;
	struct os_reltime last_ts;
	struct os_reltime base_ts;
};

struct wifi_stats_agg_result {
	double value;
	double base_delta;
	enum wifi_stats_agg_type algorithm;
	int actual_points;
	char timeframe_str[16];
};

void wifi_stats_accum_update(struct wifi_stats_accum *acc, double value,
			     double base, const struct os_reltime *now,
			     unsigned int ewma_weight);
void wifi_stats_accum_hold(struct wifi_stats_accum *acc,
			   unsigned int ewma_weight);
double wifi_stats_accum_value(const struct wifi_stats_accum *acc,
			      enum wifi_stats_agg_type algorithm);
void wifi_stats_timeframe_str(char *buffer, size_t buffer_len,
			      const struct os_reltime *timestamps,
			      int point_count, unsigned int max_seconds);
const char * wifi_stats_agg_type_to_str(enum wifi_stats_agg_type type);
double wifi_stats_bss_maxspeed(struct hostapd_data *hapd);
double wifi_stats_clamp_maxspeed(double mbps);
int wifi_stats_emit_bitrate(char **pos, char *end,
			    enum wifi_stats_metric_type metric,
			    const struct wifi_stats_agg_result *result,
			    const struct wifi_stats_sample *latest,
			    struct wifi_stats_ctx *ctx);
int wifi_stats_emit_rssi(char **pos, char *end,
			 const struct wifi_stats_agg_result *result,
			 const struct wifi_stats_sample *latest,
			 struct wifi_stats_ctx *ctx);
int wifi_stats_emit_pct(char **pos, char *end,
			enum wifi_stats_metric_type metric,
			const struct wifi_stats_agg_result *result,
			const struct wifi_stats_sample *latest,
			struct wifi_stats_ctx *ctx);

#endif /* WIFI_STATS_I_H */
