/*
 * WBA Quality Metrics - RADIUS Vendor-Specific Attributes
 * Copyright (c) 2026, Nova Labs
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <fcntl.h>
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


/* noise stored as offset binary (nf + 128) so signed dBm maps to u32 */
#define WBA_QM_NOISE_OFFSET 128

#define WBA_QM_RTT_TIMEOUT_MS 1000
#define WBA_QM_RTT_FALLBACK_THRESHOLD 3
#define WBA_QM_RTT_BUF_SIZE 10
#define WBA_QM_RTT_DEFAULT_INTERVAL 60

/* ICMP constants — not pulling netinet/ip_icmp.h to keep
 * cross-compilation simple on openwrt toolchains */
#define WBA_QM_ICMP_ECHO_REQUEST 8
#define WBA_QM_ICMP_ECHO_REPLY   0

struct wba_qm_icmp_echo {
	u8 type;
	u8 code;
	u8 checksum[2];
	u8 id[2];
	u8 seq[2];
};

/* minimal IP header — only need ihl + protocol + src to match
 * ICMP replies; avoids pulling netinet/ip.h across toolchains */
struct wba_qm_iphdr {
	u8 ver_ihl;
	u8 tos;
	u8 tot_len[2];
	u8 id[2];
	u8 frag[2];
	u8 ttl;
	u8 protocol;
	u8 check[2];
	u8 saddr[4];
	u8 daddr[4];
};

/* host byte order — converted via htonl() at use sites */
static const u32 wba_qm_rtt_defaults[] = {
	0x01010101, /* 1.1.1.1 */
	0x08080808, /* 8.8.8.8 */
	0x09090909, /* 9.9.9.9 */
};
#define WBA_QM_RTT_NUM_DEFAULTS (sizeof(wba_qm_rtt_defaults) / \
				 sizeof(wba_qm_rtt_defaults[0]))

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

	struct wba_qm_circular noise_buf;
	struct wba_qm_ema noise_ema;

	int rtt_sock;
	u32 rtt_target;
	u16 rtt_seq;
	u16 rtt_id;
	struct os_reltime rtt_send_time;
	int rtt_pending;
	struct wba_qm_circular rtt_buf;
	int rtt_consecutive_failures;
	int rtt_fallback_idx;
	int rtt_timer_active;
};


static void wba_qm_timer_cb(void *eloop_data, void *user_data);
static void wba_qm_rtt_timer_cb(void *eloop_data, void *user_data);
static void wba_qm_rtt_rx(int sock, void *eloop_ctx, void *sock_ctx);
static void wba_qm_rtt_timeout_cb(void *eloop_data, void *user_data);
static void wba_qm_circular_push(struct wba_qm_circular *cb, u32 value);
static u32 wba_qm_circular_average(struct wba_qm_circular *cb);

static inline void wba_qm_circular_reset(struct wba_qm_circular *cb)
{
	cb->count = 0;
	cb->head = 0;
}


/* --- WAN-RTT ICMP probing --- */

static u16 wba_qm_icmp_checksum(const void *data, size_t len)
{
	const u8 *p = data;
	u32 sum = 0;
	size_t idx;

	for (idx = 0; idx + 1 < len; idx += 2)
		sum += ((u16) p[idx] << 8) | p[idx + 1];
	if (idx < len)
		sum += (u16) p[idx] << 8;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return host_to_be16((u16) ~sum);
}


static void wba_qm_rtt_select_target(struct wba_qm_ctx *ctx)
{
	struct hostapd_config *conf = ctx->iface->conf;

	if (conf->wba_qm_wan_rtt_target != 0) {
		ctx->rtt_target = conf->wba_qm_wan_rtt_target;
	} else {
		ctx->rtt_target = htonl(wba_qm_rtt_defaults[0]);
	}
	ctx->rtt_fallback_idx = 0;
	ctx->rtt_consecutive_failures = 0;
}


static void wba_qm_rtt_rotate_target(struct wba_qm_ctx *ctx)
{
	struct hostapd_config *conf = ctx->iface->conf;
	struct in_addr old_addr, new_addr;

	old_addr.s_addr = ctx->rtt_target;

	/* if user configured a target, it occupies slot 0 in the
	 * logical list, with the defaults following after it */
	if (conf->wba_qm_wan_rtt_target != 0) {
		ctx->rtt_fallback_idx++;
		if ((size_t) ctx->rtt_fallback_idx >
		    WBA_QM_RTT_NUM_DEFAULTS)
			ctx->rtt_fallback_idx = 0;

		if (ctx->rtt_fallback_idx == 0)
			ctx->rtt_target = conf->wba_qm_wan_rtt_target;
		else
			ctx->rtt_target = htonl(
				wba_qm_rtt_defaults[ctx->rtt_fallback_idx - 1]);
	} else {
		ctx->rtt_fallback_idx =
			(ctx->rtt_fallback_idx + 1) %
			(int) WBA_QM_RTT_NUM_DEFAULTS;
		ctx->rtt_target = htonl(
			wba_qm_rtt_defaults[ctx->rtt_fallback_idx]);
	}

	ctx->rtt_consecutive_failures = 0;
	wba_qm_circular_reset(&ctx->rtt_buf);

	/* inet_ntoa returns static buffer, can't use twice
	 * in one printf call */
	new_addr.s_addr = ctx->rtt_target;
	wpa_printf(MSG_DEBUG,
		   "wba_qm: rtt fallback from %s", inet_ntoa(old_addr));
	wpa_printf(MSG_DEBUG,
		   "wba_qm: rtt new target %s", inet_ntoa(new_addr));
}


static int wba_qm_rtt_open_sock(struct wba_qm_ctx *ctx)
{
	int sock, flags;

	if (ctx->rtt_sock >= 0)
		return 0;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		wpa_printf(MSG_WARNING,
			   "wba_qm: failed to open ICMP socket: %s",
			   strerror(errno));
		return -1;
	}

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
		wpa_printf(MSG_WARNING,
			   "wba_qm: failed to set ICMP socket non-blocking");
		close(sock);
		return -1;
	}

	if (eloop_register_read_sock(sock, wba_qm_rtt_rx, ctx, NULL) != 0) {
		wpa_printf(MSG_WARNING,
			   "wba_qm: failed to register ICMP socket with eloop");
		close(sock);
		return -1;
	}

	ctx->rtt_sock = sock;
	ctx->rtt_id = (u16)(getpid() & 0xFFFF);
	wpa_printf(MSG_DEBUG, "wba_qm: rtt socket opened fd=%d id=0x%04x",
		   sock, ctx->rtt_id);
	return 0;
}


static void wba_qm_rtt_close_sock(struct wba_qm_ctx *ctx)
{
	if (ctx->rtt_sock < 0)
		return;

	eloop_cancel_timeout(wba_qm_rtt_timeout_cb, ctx, NULL);
	eloop_unregister_read_sock(ctx->rtt_sock);
	close(ctx->rtt_sock);
	ctx->rtt_sock = -1;
	ctx->rtt_pending = 0;
	wpa_printf(MSG_DEBUG, "wba_qm: rtt socket closed");
}


static void wba_qm_rtt_send_probe(struct wba_qm_ctx *ctx)
{
	struct wba_qm_icmp_echo pkt;
	struct sockaddr_in dst;
	int ret;

	if (ctx->rtt_sock < 0)
		return;

	if (ctx->rtt_pending) {
		wpa_printf(MSG_MSGDUMP,
			   "wba_qm: rtt probe still pending, skipping");
		return;
	}

	os_memset(&pkt, 0, sizeof(pkt));
	pkt.type = WBA_QM_ICMP_ECHO_REQUEST;
	pkt.code = 0;
	WPA_PUT_BE16(pkt.id, ctx->rtt_id);
	WPA_PUT_BE16(pkt.seq, ctx->rtt_seq);

	/* checksum must be computed with checksum field zeroed */
	{
		u16 cksum = wba_qm_icmp_checksum(&pkt, sizeof(pkt));
		os_memcpy(pkt.checksum, &cksum, 2);
	}

	os_memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = ctx->rtt_target;

	ret = sendto(ctx->rtt_sock, &pkt, sizeof(pkt), 0,
		     (struct sockaddr *) &dst, sizeof(dst));
	if (ret < 0) {
		wpa_printf(MSG_DEBUG,
			   "wba_qm: rtt sendto failed: %s", strerror(errno));
		ctx->rtt_consecutive_failures++;
		if (ctx->rtt_consecutive_failures >=
		    WBA_QM_RTT_FALLBACK_THRESHOLD)
			wba_qm_rtt_rotate_target(ctx);
		return;
	}

	os_get_reltime(&ctx->rtt_send_time);
	ctx->rtt_pending = 1;

	if (eloop_register_timeout(0, WBA_QM_RTT_TIMEOUT_MS * 1000,
				   wba_qm_rtt_timeout_cb, ctx, NULL) != 0) {
		wpa_printf(MSG_WARNING,
			   "wba_qm: failed to register rtt timeout");
		ctx->rtt_pending = 0;
	}

	wpa_printf(MSG_MSGDUMP,
		   "wba_qm: rtt probe sent seq=%u target=%s",
		   ctx->rtt_seq, inet_ntoa(dst.sin_addr));

	ctx->rtt_seq++;
}


static void wba_qm_rtt_rx(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wba_qm_ctx *ctx = eloop_ctx;
	u8 rxbuf[128];
	ssize_t len;
	struct wba_qm_iphdr *iph;
	struct wba_qm_icmp_echo *icmp;
	int ihl;
	struct os_reltime now, delta;
	u32 rtt_ms;

	len = recv(sock, rxbuf, sizeof(rxbuf), 0);
	if (len < 0)
		return;

	if ((size_t) len < sizeof(struct wba_qm_iphdr))
		return;

	iph = (struct wba_qm_iphdr *) rxbuf;
	ihl = (iph->ver_ihl & 0x0F) * 4;

	if (ihl < (int) sizeof(struct wba_qm_iphdr))
		return;

	if (iph->protocol != IPPROTO_ICMP)
		return;

	if ((size_t) len < (size_t) ihl + sizeof(struct wba_qm_icmp_echo))
		return;

	icmp = (struct wba_qm_icmp_echo *) (rxbuf + ihl);

	if (icmp->type != WBA_QM_ICMP_ECHO_REPLY || icmp->code != 0)
		return;

	if (WPA_GET_BE16(icmp->id) != ctx->rtt_id)
		return;

	if (!ctx->rtt_pending)
		return;

	/* validate source IP and seq to reject late replies
	 * from a previous target after fallback rotation */
	if (os_memcmp(iph->saddr, &ctx->rtt_target, 4) != 0)
		return;

	if (WPA_GET_BE16(icmp->seq) != (u16)(ctx->rtt_seq - 1))
		return;

	eloop_cancel_timeout(wba_qm_rtt_timeout_cb, ctx, NULL);
	ctx->rtt_pending = 0;

	os_get_reltime(&now);
	os_reltime_sub(&now, &ctx->rtt_send_time, &delta);

	rtt_ms = (u32)(delta.sec * 1000 + delta.usec / 1000);
	if (rtt_ms > 999)
		rtt_ms = 999;

	wba_qm_circular_push(&ctx->rtt_buf, rtt_ms);
	ctx->rtt_consecutive_failures = 0;

	wpa_printf(MSG_DEBUG, "wba_qm: rtt reply seq=%u rtt=%ums",
		   WPA_GET_BE16(icmp->seq), rtt_ms);
}


static void wba_qm_rtt_timeout_cb(void *eloop_data, void *user_data)
{
	struct wba_qm_ctx *ctx = eloop_data;

	if (!ctx->rtt_pending)
		return;

	ctx->rtt_pending = 0;
	ctx->rtt_consecutive_failures++;

	wpa_printf(MSG_DEBUG,
		   "wba_qm: rtt probe timeout (consecutive=%d)",
		   ctx->rtt_consecutive_failures);

	if (ctx->rtt_consecutive_failures >= WBA_QM_RTT_FALLBACK_THRESHOLD)
		wba_qm_rtt_rotate_target(ctx);
}


static u32 wba_qm_rtt_get(struct wba_qm_ctx *ctx)
{
	if (ctx->rtt_buf.count == 0)
		return 0;
	return wba_qm_circular_average(&ctx->rtt_buf);
}


static void wba_qm_rtt_timer_cb(void *eloop_data, void *user_data)
{
	struct wba_qm_ctx *ctx = eloop_data;
	struct hostapd_config *conf;
	unsigned int interval;

	if (!ctx || !ctx->iface || !ctx->iface->conf) {
		if (ctx)
			ctx->rtt_timer_active = 0;
		return;
	}

	conf = ctx->iface->conf;

	wba_qm_rtt_send_probe(ctx);

	interval = conf->wba_qm_wan_rtt_interval;
	if (interval < 1)
		interval = WBA_QM_RTT_DEFAULT_INTERVAL;

	if (eloop_register_timeout(interval, 0, wba_qm_rtt_timer_cb,
				   ctx, NULL) != 0) {
		ctx->rtt_timer_active = 0;
		wpa_printf(MSG_ERROR,
			   "wba_qm: failed to re-register rtt timer");
	}
}


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


/* --- noise averaging --- */

static int wba_qm_get_noise(struct wba_qm_ctx *ctx,
			     struct hostapd_config *conf)
{
	int instant = (int) ctx->iface->lowest_nf;

	switch (conf->wba_qm_noise_avg_type) {
	case WBA_QM_AVG_LINEAR:
		if (ctx->noise_buf.count > 0)
			return (int) wba_qm_circular_average(&ctx->noise_buf) -
				WBA_QM_NOISE_OFFSET;
		return instant;
	case WBA_QM_AVG_EXPONENTIAL:
		if (ctx->noise_ema.initialized)
			return (int) wba_qm_ema_get(&ctx->noise_ema) -
				WBA_QM_NOISE_OFFSET;
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

	if (ctx->iface->chans_surveyed > 0) {
		u32 nf_offset = (u32)((int) ctx->iface->lowest_nf +
				      WBA_QM_NOISE_OFFSET);

		switch (conf->wba_qm_noise_avg_type) {
		case WBA_QM_AVG_LINEAR:
			wba_qm_circular_push(&ctx->noise_buf, nf_offset);
			wpa_printf(MSG_MSGDUMP,
				   "wba_qm: sampled noise=%d buf_count=%zu",
				   ctx->iface->lowest_nf,
				   ctx->noise_buf.count);
			break;
		case WBA_QM_AVG_EXPONENTIAL:
			wba_qm_ema_update(&ctx->noise_ema, nf_offset,
					   conf->wba_qm_noise_avg_param);
			wpa_printf(MSG_MSGDUMP,
				   "wba_qm: sampled noise=%d ema=%d",
				   ctx->iface->lowest_nf,
				   wba_qm_get_noise(ctx, conf));
			break;
		default:
			break;
		}
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

struct wba_qm_ctx * wba_qm_init(struct hostapd_iface *iface)
{
	struct wba_qm_ctx *ctx;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->iface = iface;
	ctx->rtt_sock = -1;
	wba_qm_rtt_select_target(ctx);

	wpa_printf(MSG_DEBUG, "wba_qm: initialized");
	return ctx;
}


void wba_qm_deinit(struct wba_qm_ctx *ctx)
{
	if (!ctx)
		return;

	wba_qm_stop_timer(ctx);
	wba_qm_rtt_close_sock(ctx);
	os_free(ctx->cu_buf);
	wba_qm_circular_free(&ctx->sta_buf);
	wba_qm_circular_free(&ctx->noise_buf);
	wba_qm_circular_free(&ctx->rtt_buf);
	wpa_printf(MSG_DEBUG, "wba_qm: deinitialized");
	os_free(ctx);
}


static int wba_qm_needs_timer(struct hostapd_config *conf)
{
	return conf->wba_qm_chan_util_acc > 0 ||
	       conf->wba_qm_sta_count_avg_type != WBA_QM_AVG_NONE ||
	       conf->wba_qm_noise_avg_type != WBA_QM_AVG_NONE;
}


static void wba_qm_rtt_stop(struct wba_qm_ctx *ctx)
{
	if (ctx->rtt_timer_active) {
		eloop_cancel_timeout(wba_qm_rtt_timer_cb, ctx, NULL);
		ctx->rtt_timer_active = 0;
	}
	wba_qm_rtt_close_sock(ctx);
}


static int wba_qm_rtt_start(struct wba_qm_ctx *ctx)
{
	struct hostapd_config *conf = ctx->iface->conf;
	unsigned int rtt_interval;

	wba_qm_rtt_stop(ctx);
	wba_qm_rtt_select_target(ctx);
	wba_qm_circular_reset(&ctx->rtt_buf);

	if (!conf->wba_qm_enabled || !conf->wba_qm_wan_rtt_enabled)
		return 0;

	if (wba_qm_rtt_open_sock(ctx) != 0)
		return -1;

	if (wba_qm_circular_alloc(&ctx->rtt_buf,
				   WBA_QM_RTT_BUF_SIZE, 1) != 0) {
		wpa_printf(MSG_ERROR,
			   "wba_qm: failed to allocate rtt circular buffer");
		wba_qm_rtt_close_sock(ctx);
		return -1;
	}

	rtt_interval = conf->wba_qm_wan_rtt_interval;
	if (rtt_interval < 1)
		rtt_interval = WBA_QM_RTT_DEFAULT_INTERVAL;

	if (eloop_register_timeout(rtt_interval, 0, wba_qm_rtt_timer_cb,
				   ctx, NULL) != 0) {
		wpa_printf(MSG_ERROR,
			   "wba_qm: failed to register rtt timer");
		wba_qm_rtt_close_sock(ctx);
		return -1;
	}

	ctx->rtt_timer_active = 1;
	wpa_printf(MSG_DEBUG, "wba_qm: rtt timer started, interval=%u",
		   rtt_interval);

	/* send first probe immediately so early RADIUS messages
	 * have RTT data without waiting a full interval */
	wba_qm_rtt_send_probe(ctx);
	return 0;
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

	/* noise averaging */
	if (conf->wba_qm_noise_avg_type == WBA_QM_AVG_LINEAR) {
		wba_qm_ema_reset(&ctx->noise_ema);
		if (wba_qm_circular_alloc(&ctx->noise_buf,
				      conf->wba_qm_noise_avg_param,
				      conf->wba_qm_interval) != 0) {
			wpa_printf(MSG_ERROR,
				   "wba_qm: failed to allocate noise circular buffer");
			return -1;
		}
	} else if (conf->wba_qm_noise_avg_type ==
		   WBA_QM_AVG_EXPONENTIAL) {
		wba_qm_circular_free(&ctx->noise_buf);
		wba_qm_ema_reset(&ctx->noise_ema);
	} else {
		wba_qm_circular_free(&ctx->noise_buf);
		wba_qm_ema_reset(&ctx->noise_ema);
	}

	/* WAN-RTT — independent timer */
	wba_qm_rtt_start(ctx);

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

	wba_qm_rtt_stop(ctx);

	if (ctx->timer_active) {
		eloop_cancel_timeout(wba_qm_timer_cb, ctx, NULL);
		ctx->timer_active = 0;
		wpa_printf(MSG_DEBUG, "wba_qm: timer stopped");
	}
}


void wba_qm_restart_rtt(struct wba_qm_ctx *ctx)
{
	if (!ctx)
		return;
	wba_qm_rtt_start(ctx);
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

	/* WBA-Min-RSSI (sub-type 104) — explicit config or derived from
	 * rssi_reject_assoc_rssi (the functional association threshold) */
	{
		int min_rssi = 0;
		int have_min_rssi = 0;

		if (conf->wba_qm_min_rssi_configured) {
			min_rssi = conf->wba_qm_min_rssi;
			have_min_rssi = 1;
		} else if (conf->rssi_reject_assoc_rssi &&
			   conf->rssi_reject_assoc_rssi >= -128 &&
			   conf->rssi_reject_assoc_rssi <= 0) {
			min_rssi = conf->rssi_reject_assoc_rssi;
			have_min_rssi = 1;
		}

		if (have_min_rssi) {
			if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_MIN_RSSI,
						(u32) min_rssi,
						"Min-RSSI") == 0)
				wpa_printf(MSG_DEBUG,
					   "wba_qm: added Min-RSSI rssi=%d%s",
					   min_rssi,
					   conf->wba_qm_min_rssi_configured ?
					   "" : " (from rssi_reject_assoc_rssi)");
		}
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

	/* WBA-Noise (sub-type 109) — optionally averaged */
	if (ctx->iface->chans_surveyed > 0) {
		int noise = wba_qm_get_noise(ctx, conf);

		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_NOISE,
					(u32) noise, "Noise") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Noise=%d", noise);
	}

	/* WBA-Noise-lin-avg (110) or Noise-exp-avg (111) */
	if (ctx->iface->chans_surveyed > 0) {
		if (conf->wba_qm_noise_avg_type == WBA_QM_AVG_LINEAR) {
			if (wba_qm_add_vsa_u32(
				    msg, RADIUS_WBA_ATTR_NOISE_LIN_AVG,
				    (u32) conf->wba_qm_noise_avg_param,
				    "Noise-lin-avg") == 0)
				wpa_printf(MSG_DEBUG,
					   "wba_qm: added Noise-lin-avg=%d",
					   conf->wba_qm_noise_avg_param);
		} else if (conf->wba_qm_noise_avg_type ==
			   WBA_QM_AVG_EXPONENTIAL) {
			if (wba_qm_add_vsa_u32(
				    msg, RADIUS_WBA_ATTR_NOISE_EXP_AVG,
				    (u32) conf->wba_qm_noise_avg_param,
				    "Noise-exp-avg") == 0)
				wpa_printf(MSG_DEBUG,
					   "wba_qm: added Noise-exp-avg=%d",
					   conf->wba_qm_noise_avg_param);
		}
	}

	/* WBA-WAN-RTT (sub-type 100) */
	if (conf->wba_qm_wan_rtt_enabled && ctx->rtt_buf.count > 0) {
		u32 rtt = wba_qm_rtt_get(ctx);

		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_WAN_RTT,
					rtt, "WAN-RTT") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added WAN-RTT=%u ms", rtt);
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
		int noise = wba_qm_get_noise(ctx, conf);

		written = os_snprintf(pos, remaining,
				      "noise_floor=%d\n"
				      "noise=%d\n"
				      "wba_qm_noise_avg=%s",
				      ctx->iface->lowest_nf,
				      noise,
				      conf->wba_qm_noise_avg_type ==
					WBA_QM_AVG_LINEAR ? "linear" :
				      conf->wba_qm_noise_avg_type ==
					WBA_QM_AVG_EXPONENTIAL ?
					"exponential" : "none");
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;

		if (conf->wba_qm_noise_avg_type != WBA_QM_AVG_NONE) {
			written = os_snprintf(pos, remaining, " %d",
					      conf->wba_qm_noise_avg_param);
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

	{
		int min_rssi = 0;
		const char *min_rssi_src = NULL;

		if (conf->wba_qm_min_rssi_configured) {
			min_rssi = conf->wba_qm_min_rssi;
			min_rssi_src = "config";
		} else if (conf->rssi_reject_assoc_rssi &&
			   conf->rssi_reject_assoc_rssi >= -128 &&
			   conf->rssi_reject_assoc_rssi <= 0) {
			min_rssi = conf->rssi_reject_assoc_rssi;
			min_rssi_src = "rssi_reject_assoc_rssi";
			   }

		if (min_rssi_src) {
			written = os_snprintf(pos, remaining,
						  "min_rssi=%d\n"
						  "min_rssi_source=%s\n",
						  min_rssi, min_rssi_src);
			if (os_snprintf_error(remaining, written))
				return -1;
			pos += written;
			remaining -= written;
		}
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

	written = os_snprintf(pos, remaining,
			      "wan_rtt_enabled=%d\n",
			      conf->wba_qm_wan_rtt_enabled);
	if (os_snprintf_error(remaining, written))
		return -1;
	pos += written;
	remaining -= written;

	if (conf->wba_qm_wan_rtt_enabled && ctx->rtt_target != 0) {
		struct in_addr target_addr;

		target_addr.s_addr = ctx->rtt_target;
		written = os_snprintf(pos, remaining,
				      "wan_rtt_target=%s\n",
				      inet_ntoa(target_addr));
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;

		written = os_snprintf(pos, remaining,
				      "wan_rtt_interval=%u\n",
				      conf->wba_qm_wan_rtt_interval);
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;

		if (ctx->rtt_buf.count > 0) {
			written = os_snprintf(pos, remaining,
					      "wan_rtt=%u\n",
					      wba_qm_rtt_get(ctx));
			if (os_snprintf_error(remaining, written))
				return -1;
			pos += written;
			remaining -= written;
		}

		written = os_snprintf(pos, remaining,
				      "wan_rtt_samples=%zu\n",
				      ctx->rtt_buf.count);
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;
	}

	return pos - buf;
}
