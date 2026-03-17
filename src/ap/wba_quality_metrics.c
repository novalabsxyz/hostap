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


void wba_qm_add_radius_attrs(struct wba_qm_ctx *ctx,
			      struct hostapd_data *hapd,
			      struct radius_msg *msg)
{
	u8 op_class, channel;
	u8 oc_buf[4];

	if (!ctx || !hapd || !msg)
		return;

	if (!ctx->iface || !ctx->iface->conf ||
	    !ctx->iface->conf->wba_qm_enabled)
		return;

	/* WBA-Wi-Fi-Global-OC (sub-type 105) */
	if (wba_qm_resolve_oc(ctx, &op_class, &channel) == 0) {
		/* RADIUS integer: 4 bytes big-endian (RFC 8044) */
		WPA_PUT_BE32(oc_buf, (u32) op_class);
		if (!radius_msg_add_wba(msg, RADIUS_WBA_ATTR_WIFI_GLOBAL_OC,
					oc_buf, sizeof(oc_buf)))
			wpa_printf(MSG_WARNING,
				   "wba_qm: failed to add Wi-Fi-Global-OC");
		else
			wpa_printf(MSG_DEBUG,
				   "wba_qm: added Wi-Fi-Global-OC op_class=%u channel=%u",
				   op_class, channel);
	} else {
		wpa_printf(MSG_DEBUG,
			   "wba_qm: skipping Wi-Fi-Global-OC, freq=%d unresolvable",
			   ctx->iface->freq);
	}
}


int wba_qm_get_status(struct wba_qm_ctx *ctx, char *buf, size_t buflen)
{
	char *pos = buf;
	size_t remaining = buflen;
	int written;
	u8 op_class = 0, channel = 0;

	if (!ctx || !ctx->iface || !buf || buflen == 0)
		return -1;

	if (!ctx->iface->conf)
		return -1;

	wba_qm_resolve_oc(ctx, &op_class, &channel);

	written = os_snprintf(pos, remaining,
			      "wba_qm_enabled=%d\n"
			      "freq=%d\n"
			      "wifi_global_oc=%u\n"
			      "operating_channel=%u\n",
			      ctx->iface->conf->wba_qm_enabled,
			      ctx->iface->freq,
			      op_class, channel);
	if (os_snprintf_error(remaining, written))
		return -1;
	pos += written;

	return pos - buf;
}
