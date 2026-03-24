/*
 * WBA Quality Metrics - RADIUS Vendor-Specific Attributes
 * Copyright (c) 2026, Nova Labs
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_common.h"
#include "radius/radius.h"
#include "ap_config.h"
#include "hostapd.h"
#include "wba_quality_metrics.h"


struct wba_qm_cu_sample {
	u64 busy_delta;
	u64 total_delta;
};


struct wba_qm_circular {
	u32 *buf;
	size_t size;
	size_t count;
	size_t head;
};


struct wba_qm_ema {
	u32 accum;
	int initialized;
};


struct wba_qm_ctx {
	struct hostapd_iface *iface;
	int timer_active;

	/* chan-util accumulation circular buffer (spec section 3.3) */
	struct wba_qm_cu_sample *cu_buf;
	size_t cu_buf_size;
	size_t cu_buf_count;
	size_t cu_buf_head;
	u64 cu_prev_time;
	u64 cu_prev_time_busy;
	int cu_initialized;

	struct wba_qm_circular sta_buf;
	struct wba_qm_ema sta_ema;
};


static void wba_qm_timer_cb(void *eloop_data, void *user_data);


static int wba_qm_resolve_oc(struct wba_qm_ctx *ctx, u8 *op_class,
			      u8 *channel)
{
	struct hostapd_config *conf;

	if (!ctx || !ctx->iface)
		return -1;

	conf = ctx->iface->conf;
	if (!conf)
		return -1;

	if (ieee80211_freq_to_channel_ext(ctx->iface->freq,
					  conf->secondary_channel,
					  hostapd_get_oper_chwidth(conf),
					  op_class,
					  channel) == NUM_HOSTAPD_MODES)
		return -1;

	return 0;
}


/* --- chan-util accumulation (uses separate struct, not generic circular buf) --- */

static int wba_qm_cu_buf_alloc(struct wba_qm_ctx *ctx, int window,
				int interval)
{
	size_t new_size;
	struct wba_qm_cu_sample *new_buf;

	if (interval <= 0)
		interval = 1;
	new_size = (size_t)(window / interval) + 1;
	if (new_size < 1)
		new_size = 1;

	if (ctx->cu_buf && ctx->cu_buf_size == new_size)
		return 0;

	new_buf = os_zalloc(new_size * sizeof(struct wba_qm_cu_sample));
	if (!new_buf)
		return -1;

	os_free(ctx->cu_buf);
	ctx->cu_buf = new_buf;
	ctx->cu_buf_size = new_size;
	ctx->cu_buf_count = 0;
	ctx->cu_buf_head = 0;

	return 0;
}


static void wba_qm_cu_buf_push(struct wba_qm_ctx *ctx, u64 busy_delta,
				u64 total_delta)
{
	if (!ctx->cu_buf || ctx->cu_buf_size == 0)
		return;

	ctx->cu_buf[ctx->cu_buf_head].busy_delta = busy_delta;
	ctx->cu_buf[ctx->cu_buf_head].total_delta = total_delta;
	ctx->cu_buf_head = (ctx->cu_buf_head + 1) % ctx->cu_buf_size;
	if (ctx->cu_buf_count < ctx->cu_buf_size)
		ctx->cu_buf_count++;
}


static int wba_qm_cu_get_accumulated(struct wba_qm_ctx *ctx,
				     u32 *percent_out,
				     u32 *acc_seconds_out)
{
	u64 sum_busy = 0, sum_total = 0;
	size_t idx, pos;
	struct hostapd_config *conf;

	if (!ctx->cu_buf || ctx->cu_buf_count == 0)
		return -1;

	conf = ctx->iface->conf;

	for (idx = 0; idx < ctx->cu_buf_count; idx++) {
		pos = (ctx->cu_buf_head + ctx->cu_buf_size -
		       ctx->cu_buf_count + idx) % ctx->cu_buf_size;
		sum_busy += ctx->cu_buf[pos].busy_delta;
		sum_total += ctx->cu_buf[pos].total_delta;
	}

	if (sum_total == 0)
		return -1;

	*percent_out = (u32)(sum_busy * 100 / sum_total);
	*acc_seconds_out = (u32)(ctx->cu_buf_count * conf->wba_qm_interval);
	return 0;
}


static void wba_qm_cu_sample(struct wba_qm_ctx *ctx)
{
	u64 cur_time, cur_busy;
	u64 busy_delta, total_delta;

	cur_time = ctx->iface->last_channel_time;
	cur_busy = ctx->iface->last_channel_time_busy;

	if (cur_time == 0)
		return;

	if (!ctx->cu_initialized) {
		ctx->cu_prev_time = cur_time;
		ctx->cu_prev_time_busy = cur_busy;
		ctx->cu_initialized = 1;
		return;
	}

	if (cur_time <= ctx->cu_prev_time) {
		ctx->cu_prev_time = cur_time;
		ctx->cu_prev_time_busy = cur_busy;
		return;
	}

	total_delta = cur_time - ctx->cu_prev_time;
	busy_delta = cur_busy - ctx->cu_prev_time_busy;

	if (busy_delta > total_delta)
		busy_delta = total_delta;

	wba_qm_cu_buf_push(ctx, busy_delta, total_delta);
	wpa_printf(MSG_MSGDUMP,
		   "wba_qm: cu sample busy=%llu total=%llu buf_count=%zu",
		   (unsigned long long) busy_delta,
		   (unsigned long long) total_delta,
		   ctx->cu_buf_count);

	ctx->cu_prev_time = cur_time;
	ctx->cu_prev_time_busy = cur_busy;
}


/* --- generic u32 circular buffer and EWMA --- */

static int wba_qm_circular_alloc(struct wba_qm_circular *cb, int window,
			      int interval)
{
	size_t new_size;
	u32 *new_buf;

	if (interval <= 0)
		interval = 1;
	new_size = (size_t)(window / interval) + 1;
	if (new_size < 1)
		new_size = 1;

	if (cb->buf && cb->size == new_size)
		return 0;

	new_buf = os_zalloc(new_size * sizeof(u32));
	if (!new_buf)
		return -1;

	os_free(cb->buf);
	cb->buf = new_buf;
	cb->size = new_size;
	cb->count = 0;
	cb->head = 0;

	return 0;
}


static void wba_qm_circular_push(struct wba_qm_circular *cb, u32 value)
{
	if (!cb->buf || cb->size == 0)
		return;

	cb->buf[cb->head] = value;
	cb->head = (cb->head + 1) % cb->size;
	if (cb->count < cb->size)
		cb->count++;
}


static u32 wba_qm_circular_average(struct wba_qm_circular *cb)
{
	size_t idx;
	u64 sum = 0;

	if (cb->count == 0)
		return 0;

	for (idx = 0; idx < cb->count; idx++)
		sum += cb->buf[idx];

	return (u32)(sum / cb->count);
}


static void wba_qm_circular_free(struct wba_qm_circular *cb)
{
	os_free(cb->buf);
	os_memset(cb, 0, sizeof(*cb));
}


/* EWMA with alpha = 2/(2^weight + 1), fixed-point *1024 */
static void wba_qm_ema_update(struct wba_qm_ema *ema, u32 sample, int weight)
{
	u32 divisor, scaled;

	if (weight > 20)
		weight = 20;
	divisor = (1U << weight) + 1;
	scaled = sample * 1024;

	if (!ema->initialized) {
		ema->accum = scaled;
		ema->initialized = 1;
		return;
	}

	if (scaled >= ema->accum)
		ema->accum += (2 * (scaled - ema->accum)) / divisor;
	else
		ema->accum -= (2 * (ema->accum - scaled)) / divisor;
}


static u32 wba_qm_ema_get(struct wba_qm_ema *ema)
{
	if (!ema->initialized)
		return 0;
	return (ema->accum + 512) / 1024;
}


static void wba_qm_ema_reset(struct wba_qm_ema *ema)
{
	ema->accum = 0;
	ema->initialized = 0;
}


/* --- sta-count averaging --- */

static u32 wba_qm_get_sta_count(struct wba_qm_ctx *ctx,
				 struct hostapd_config *conf)
{
	u32 instant = (u32) hostapd_iface_num_sta(ctx->iface);

	switch (conf->wba_qm_sta_count_avg_type) {
	case WBA_QM_AVG_LINEAR:
		if (ctx->sta_buf.count > 0)
			return wba_qm_circular_average(&ctx->sta_buf);
		return instant;
	case WBA_QM_AVG_EXPONENTIAL:
		if (ctx->sta_ema.initialized)
			return wba_qm_ema_get(&ctx->sta_ema);
		return instant;
	default:
		return instant;
	}
}


/* --- periodic sampling --- */

static void wba_qm_sample(struct wba_qm_ctx *ctx)
{
	struct hostapd_config *conf;
	u32 sta_count;

	if (!ctx->iface || !ctx->iface->conf)
		return;

	conf = ctx->iface->conf;

	if (conf->wba_qm_chan_util_acc > 0)
		wba_qm_cu_sample(ctx);

	sta_count = (u32) hostapd_iface_num_sta(ctx->iface);
	switch (conf->wba_qm_sta_count_avg_type) {
	case WBA_QM_AVG_LINEAR:
		wba_qm_circular_push(&ctx->sta_buf, sta_count);
		wpa_printf(MSG_MSGDUMP,
			   "wba_qm: sampled sta_count=%u buf_count=%zu",
			   sta_count, ctx->sta_buf.count);
		break;
	case WBA_QM_AVG_EXPONENTIAL:
		wba_qm_ema_update(&ctx->sta_ema, sta_count,
				   conf->wba_qm_sta_count_avg_param);
		wpa_printf(MSG_MSGDUMP,
			   "wba_qm: sampled sta_count=%u ema=%u",
			   sta_count, wba_qm_ema_get(&ctx->sta_ema));
		break;
	default:
		break;
	}
}


static void wba_qm_timer_cb(void *eloop_data, void *user_data)
{
	struct wba_qm_ctx *ctx = eloop_data;
	struct hostapd_config *conf;
	int interval;

	if (!ctx || !ctx->iface || !ctx->iface->conf) {
		if (ctx)
			ctx->timer_active = 0;
		return;
	}

	conf = ctx->iface->conf;

	wba_qm_sample(ctx);

	interval = conf->wba_qm_interval;
	if (interval < 1)
		interval = 1;

	if (eloop_register_timeout(interval, 0, wba_qm_timer_cb,
				   ctx, NULL) != 0) {
		ctx->timer_active = 0;
		wpa_printf(MSG_ERROR,
			   "wba_qm: failed to re-register timer");
	}
}


/* --- lifecycle --- */

static int wba_qm_needs_timer(struct hostapd_config *conf)
{
	return conf->wba_qm_chan_util_acc > 0 ||
	       conf->wba_qm_sta_count_avg_type != WBA_QM_AVG_NONE;
}


struct wba_qm_ctx * wba_qm_init(struct hostapd_iface *iface)
{
	struct wba_qm_ctx *ctx;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->iface = iface;

	wpa_printf(MSG_DEBUG, "wba_qm: initialized");
	return ctx;
}


void wba_qm_deinit(struct wba_qm_ctx *ctx)
{
	if (!ctx)
		return;

	wba_qm_stop_timer(ctx);
	os_free(ctx->cu_buf);
	wba_qm_circular_free(&ctx->sta_buf);
	wpa_printf(MSG_DEBUG, "wba_qm: deinitialized");
	os_free(ctx);
}


int wba_qm_start_timer(struct wba_qm_ctx *ctx)
{
	struct hostapd_config *conf;
	int interval;

	if (!ctx || !ctx->iface || !ctx->iface->conf)
		return -1;

	conf = ctx->iface->conf;

	eloop_cancel_timeout(wba_qm_timer_cb, ctx, NULL);
	ctx->timer_active = 0;

	if (conf->wba_qm_chan_util_acc > 0) {
		if (wba_qm_cu_buf_alloc(ctx, conf->wba_qm_chan_util_acc,
					conf->wba_qm_interval) != 0) {
			wpa_printf(MSG_ERROR,
				   "wba_qm: failed to allocate cu circular buffer");
			return -1;
		}
	}

	/* sta-count averaging */
	if (conf->wba_qm_sta_count_avg_type == WBA_QM_AVG_LINEAR) {
		wba_qm_ema_reset(&ctx->sta_ema);
		if (wba_qm_circular_alloc(&ctx->sta_buf,
				      conf->wba_qm_sta_count_avg_param,
				      conf->wba_qm_interval) != 0) {
			wpa_printf(MSG_ERROR,
				   "wba_qm: failed to allocate sta circular buffer");
			return -1;
		}
	} else if (conf->wba_qm_sta_count_avg_type ==
		   WBA_QM_AVG_EXPONENTIAL) {
		wba_qm_circular_free(&ctx->sta_buf);
		wba_qm_ema_reset(&ctx->sta_ema);
	} else {
		wba_qm_circular_free(&ctx->sta_buf);
		wba_qm_ema_reset(&ctx->sta_ema);
	}

	if (!wba_qm_needs_timer(conf)) {
		wpa_printf(MSG_DEBUG,
			   "wba_qm: no averaging configured, timer not needed");
		return 0;
	}

	interval = conf->wba_qm_interval;
	if (interval < 1)
		interval = 1;

	if (eloop_register_timeout(interval, 0, wba_qm_timer_cb,
				   ctx, NULL) != 0) {
		wpa_printf(MSG_ERROR, "wba_qm: failed to register timer");
		return -1;
	}

	ctx->timer_active = 1;
	wpa_printf(MSG_DEBUG, "wba_qm: timer started, interval=%d",
		   interval);
	return 0;
}


void wba_qm_stop_timer(struct wba_qm_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->timer_active) {
		eloop_cancel_timeout(wba_qm_timer_cb, ctx, NULL);
		ctx->timer_active = 0;
		wpa_printf(MSG_DEBUG, "wba_qm: timer stopped");
	}
}


/* --- RADIUS attribute helpers --- */

static int wba_qm_add_vsa_u32(struct radius_msg *msg, u8 subtype,
			       u32 value, const char *name)
{
	u8 buf[4];

	WPA_PUT_BE32(buf, value);
	if (!radius_msg_add_wba(msg, subtype, buf, sizeof(buf))) {
		wpa_printf(MSG_WARNING, "wba_qm: failed to add %s", name);
		return -1;
	}
	return 0;
}


void wba_qm_add_radius_attrs(struct wba_qm_ctx *ctx,
			      struct hostapd_data *hapd,
			      struct radius_msg *msg)
{
	struct hostapd_config *conf;
	u8 op_class, channel;

	if (!ctx || !hapd || !msg)
		return;

	if (!ctx->iface || !ctx->iface->conf ||
	    !ctx->iface->conf->wba_qm_enabled)
		return;

	conf = ctx->iface->conf;

	/* WBA-Wi-Fi-Global-OC (sub-type 105) */
	if (wba_qm_resolve_oc(ctx, &op_class, &channel) == 0) {
		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_WIFI_GLOBAL_OC,
					(u32) op_class,
					"Wi-Fi-Global-OC") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Wi-Fi-Global-OC op_class=%u channel=%u",
				   op_class, channel);
	} else {
		wpa_printf(MSG_DEBUG,
			   "wba_qm: skipping Wi-Fi-Global-OC, freq=%d unresolvable",
			   ctx->iface->freq);
	}

	/* WBA-Noise-Floor (sub-type 103) — instantaneous survey data */
	if (ctx->iface->chans_surveyed > 0) {
		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_NOISE_FLOOR,
					(u32)(int) ctx->iface->lowest_nf,
					"Noise-Floor") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Noise-Floor nf=%d",
				   ctx->iface->lowest_nf);
	}

	/* WBA-Chan-Util (101) + optional Chan-Util-acc (102) */
	if (conf->wba_qm_chan_util_acc > 0) {
		u32 percent, acc_seconds;

		if (wba_qm_cu_get_accumulated(ctx, &percent,
					      &acc_seconds) == 0) {
			if (wba_qm_add_vsa_u32(msg,
						RADIUS_WBA_ATTR_CHAN_UTIL,
						percent,
						"Chan-Util") == 0)
				wpa_printf(MSG_DEBUG,
					   "wba_qm: added Chan-Util percent=%u (acc)",
					   percent);

			if (wba_qm_add_vsa_u32(msg,
						RADIUS_WBA_ATTR_CHAN_UTIL_ACC,
						acc_seconds,
						"Chan-Util-acc") == 0)
				wpa_printf(MSG_DEBUG,
					   "wba_qm: added Chan-Util-acc sec=%u",
					   acc_seconds);
		}
	} else if (ctx->iface->last_channel_time > 0) {
		u32 percent = (ctx->iface->channel_utilization * 100) / 255;

		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_CHAN_UTIL,
					percent, "Chan-Util") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Chan-Util percent=%u (instant)",
				   percent);
	}

	/* WBA-Min-RSSI (sub-type 104) — static config value */
	if (conf->wba_qm_min_rssi_configured) {
		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_MIN_RSSI,
					(u32) conf->wba_qm_min_rssi,
					"Min-RSSI") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Min-RSSI rssi=%d",
				   conf->wba_qm_min_rssi);
	}

	/* WBA-STA-Count (sub-type 106) */
	{
		u32 sta_count = wba_qm_get_sta_count(ctx, conf);

		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_STA_COUNT,
					sta_count, "STA-Count") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added STA-Count=%u", sta_count);
	}

	/* WBA-STA-Count-lin-avg (107) or exp-avg (108) */
	if (conf->wba_qm_sta_count_avg_type == WBA_QM_AVG_LINEAR) {
		if (wba_qm_add_vsa_u32(msg,
					RADIUS_WBA_ATTR_STA_COUNT_LIN_AVG,
					(u32) conf->wba_qm_sta_count_avg_param,
					"STA-Count-lin-avg") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added STA-Count-lin-avg=%d",
				   conf->wba_qm_sta_count_avg_param);
	} else if (conf->wba_qm_sta_count_avg_type ==
		   WBA_QM_AVG_EXPONENTIAL) {
		if (wba_qm_add_vsa_u32(msg,
					RADIUS_WBA_ATTR_STA_COUNT_EXP_AVG,
					(u32) conf->wba_qm_sta_count_avg_param,
					"STA-Count-exp-avg") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added STA-Count-exp-avg=%d",
				   conf->wba_qm_sta_count_avg_param);
	}
}


/* --- status output --- */

int wba_qm_get_status(struct wba_qm_ctx *ctx, char *buf, size_t buflen)
{
	struct hostapd_config *conf;
	char *pos = buf;
	size_t remaining = buflen;
	int written;
	u8 op_class = 0, channel = 0;

	if (!ctx || !ctx->iface || !buf || buflen == 0)
		return -1;

	conf = ctx->iface->conf;
	if (!conf)
		return -1;

	wba_qm_resolve_oc(ctx, &op_class, &channel);

	written = os_snprintf(pos, remaining,
			      "wba_qm_enabled=%d\n"
			      "freq=%d\n"
			      "wifi_global_oc=%u\n"
			      "operating_channel=%u\n",
			      conf->wba_qm_enabled,
			      ctx->iface->freq,
			      op_class, channel);
	if (os_snprintf_error(remaining, written))
		return -1;
	pos += written;
	remaining -= written;

	if (ctx->iface->chans_surveyed > 0) {
		written = os_snprintf(pos, remaining,
				      "noise_floor=%d\n",
				      ctx->iface->lowest_nf);
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;
	}

	if (conf->wba_qm_chan_util_acc > 0) {
		u32 percent, acc_seconds;

		if (wba_qm_cu_get_accumulated(ctx, &percent,
					      &acc_seconds) == 0) {
			written = os_snprintf(pos, remaining,
					      "chan_util=%u\n"
					      "chan_util_acc=%u\n",
					      percent, acc_seconds);
			if (os_snprintf_error(remaining, written))
				return -1;
			pos += written;
			remaining -= written;
		}
	} else if (ctx->iface->last_channel_time > 0) {
		u32 percent = (ctx->iface->channel_utilization * 100) / 255;

		written = os_snprintf(pos, remaining,
				      "chan_util=%u\n",
				      percent);
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;
	}

	if (conf->wba_qm_min_rssi_configured) {
		written = os_snprintf(pos, remaining,
				      "min_rssi=%d\n",
				      conf->wba_qm_min_rssi);
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;
	}

	{
		u32 sta_count = wba_qm_get_sta_count(ctx, conf);

		written = os_snprintf(pos, remaining,
				      "sta_count=%u\n"
				      "sta_count_instant=%u\n"
				      "wba_qm_interval=%d\n"
				      "wba_qm_sta_count_avg=%s",
				      sta_count,
				      (u32) hostapd_iface_num_sta(ctx->iface),
				      conf->wba_qm_interval,
				      conf->wba_qm_sta_count_avg_type ==
					WBA_QM_AVG_LINEAR ? "linear" :
				      conf->wba_qm_sta_count_avg_type ==
					WBA_QM_AVG_EXPONENTIAL ?
					"exponential" : "none");
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;

		if (conf->wba_qm_sta_count_avg_type != WBA_QM_AVG_NONE) {
			written = os_snprintf(pos, remaining, " %d",
					      conf->wba_qm_sta_count_avg_param);
			if (os_snprintf_error(remaining, written))
				return -1;
			pos += written;
			remaining -= written;
		}

		written = os_snprintf(pos, remaining, "\n");
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;
	}

	return pos - buf;
}
