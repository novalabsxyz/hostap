/*
 * WBA Quality Metrics - RADIUS Vendor-Specific Attributes
 * Copyright (c) 2026, Nova Labs
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WBA_QUALITY_METRICS_H
#define WBA_QUALITY_METRICS_H

struct hostapd_data;
struct hostapd_iface;
struct radius_msg;
struct wba_qm_ctx;

struct wba_qm_ctx * wba_qm_init(struct hostapd_iface *iface);
void wba_qm_deinit(struct wba_qm_ctx *ctx);
int wba_qm_start_timer(struct wba_qm_ctx *ctx);
void wba_qm_stop_timer(struct wba_qm_ctx *ctx);
void wba_qm_restart_rtt(struct wba_qm_ctx *ctx);
void wba_qm_add_radius_attrs(struct wba_qm_ctx *ctx,
			      struct hostapd_data *hapd,
			      struct radius_msg *msg);
int wba_qm_get_status(struct wba_qm_ctx *ctx, char *buf, size_t buflen);

#endif /* WBA_QUALITY_METRICS_H */
