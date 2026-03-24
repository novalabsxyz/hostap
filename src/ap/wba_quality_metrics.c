/*
 * WBA Quality Metrics - RADIUS Vendor-Specific Attributes
 * Copyright (c) 2026, Nova Labs
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "radius/radius.h"
#include "ap_config.h"
#include "hostapd.h"
#include "wba_quality_metrics.h"


struct wba_qm_ctx {
	struct hostapd_iface *iface;
};


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

	wpa_printf(MSG_DEBUG, "wba_qm: deinitialized");
	os_free(ctx);
}


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

	/* WBA-Min-RSSI (sub-type 104) — static config value */
	if (conf->wba_qm_min_rssi_configured) {
		if (wba_qm_add_vsa_u32(msg, RADIUS_WBA_ATTR_MIN_RSSI,
					(u32) conf->wba_qm_min_rssi,
					"Min-RSSI") == 0)
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Min-RSSI rssi=%d",
				   conf->wba_qm_min_rssi);
	}
}


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

	if (conf->wba_qm_min_rssi_configured) {
		written = os_snprintf(pos, remaining,
				      "min_rssi=%d\n",
				      conf->wba_qm_min_rssi);
		if (os_snprintf_error(remaining, written))
			return -1;
		pos += written;
		remaining -= written;
	}

	return pos - buf;
}
