/*
 * Wi-Fi statistics module tests
 * Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/module_tests.h"
#include "hostapd.h"
#include "ap_config.h"
#include "wifi_stats.h"
#include "wifi_stats_i.h"


static bool wifi_stats_test_equal(double a, double b)
{
	double diff = a - b;

	return diff > -1e-9 && diff < 1e-9;
}


static int wifi_stats_test_str(const char *buf, const char *expected)
{
	if (os_strcmp(buf, expected) == 0)
		return 0;
	wpa_printf(MSG_ERROR, "wifi_stats: '%s', expected '%s'", buf,
		   expected);
	return 1;
}


static int wifi_stats_aggregation_tests(void)
{
	/* signal in dBm; every expected value is exact in binary */
	static const double seq[] = { -60.0, -70.0, -50.0, -64.0 };
	static const struct {
		enum wifi_stats_agg_type type;
		unsigned int weight;
		double expected;
	} tests[] = {
		{ WIFI_STATS_AGG_MIN, 0, -70.0 },
		{ WIFI_STATS_AGG_MAX, 0, -50.0 },
		/* (-60 - 70 - 50 - 64) / 4 */
		{ WIFI_STATS_AGG_AVG_LIN, 0, -61.0 },
		/*
		 * e[0] = x[0], e[i] = e[i - 1] + (x[i] - e[i - 1]) / 2^weight:
		 * -60, -65, -57.5, -60.75
		 */
		{ WIFI_STATS_AGG_AVG_EXP, 1, -60.75 },
		/* -60, -60.3125, -59.990234375, -60.11553955078125 */
		{ WIFI_STATS_AGG_AVG_EXP, 5, -60.11553955078125 },
	};
	struct wifi_stats_accum acc;
	struct os_reltime ts;
	double res;
	size_t i, j;
	int errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats aggregation tests");

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		os_memset(&acc, 0, sizeof(acc));
		for (j = 0; j < ARRAY_SIZE(seq); j++) {
			ts.sec = 1000 + j;
			ts.usec = 0;
			wifi_stats_accum_update(&acc, seq[j], 0, &ts,
						tests[i].weight);
		}
		res = wifi_stats_accum_value(&acc, tests[i].type);
		if (wifi_stats_test_equal(res, tests[i].expected))
			continue;
		wpa_printf(MSG_ERROR,
			   "wifi_stats: %s weight %u: %.12f, expected %.12f",
			   wifi_stats_agg_type_to_str(tests[i].type),
			   tests[i].weight, res, tests[i].expected);
		errors++;
	}

	return errors ? -1 : 0;
}


static int wifi_stats_hold_tests(void)
{
	/*
	 * An interval with no fresh value steps the filter toward the last
	 * fresh one again: 'f' folds the value, 'h' holds. Every expected value
	 * is exact in binary.
	 */
	static const struct {
		unsigned int weight;
		/* the filter and last value carried over a REPORT reset */
		double ewma0;
		double last0;
		const char *steps;
		double values[4];
		double ewma;
		unsigned int count;
	} tests[] = {
		/* before the first fresh value there is nothing to step */
		{ 1, 0, 0, "h", { 0 }, 0.0, 0 },
		/*
		 * after a reset there is a filter but no fresh value yet: a
		 * hold would step -60 toward the carried -70, so it must not.
		 */
		{ 1, -60, -70, "h", { 0 }, -60.0, 0 },
		/* -60, then -60 + (-70 + 60) / 2 = -65 */
		{ 1, 0, 0, "ff", { -60, -70 }, -65.0, 2 },
		/* -65, then -67.5 = -65 + (-70 + 65) / 2, then -68.75 */
		{ 1, 0, 0, "ffhh", { -60, -70 }, -68.75, 2 },
		/* a fresh value after holds: -68.75 + (-50 + 68.75) / 2 */
		{ 1, 0, 0, "ffhhf", { -60, -70, -50 }, -59.375, 3 },
		/* -60, -60.3125, then -60.3125 + (-70 + 60.3125) / 32 */
		{ 5, 0, 0, "ffh", { -60, -70 }, -60.615234375, 2 },
	};
	struct wifi_stats_accum acc;
	struct os_reltime ts;
	size_t i;
	int j, v, errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats AVG-EXP hold tests");

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		os_memset(&acc, 0, sizeof(acc));
		acc.ewma = tests[i].ewma0;
		acc.ewma_valid = tests[i].ewma0 != 0.0;
		acc.last_val = tests[i].last0;
		for (j = 0, v = 0; tests[i].steps[j]; j++) {
			ts.sec = 1000 + j;
			ts.usec = 0;
			if (tests[i].steps[j] == 'h')
				wifi_stats_accum_hold(&acc, tests[i].weight);
			else
				wifi_stats_accum_update(&acc,
							tests[i].values[v++], 0,
							&ts, tests[i].weight);
		}
		if (wifi_stats_test_equal(acc.ewma, tests[i].ewma) &&
		    acc.count == tests[i].count)
			continue;
		wpa_printf(MSG_ERROR,
			   "wifi_stats: Hold %s weight %u: %.12f of %u, expected %.12f of %u",
			   tests[i].steps, tests[i].weight, acc.ewma,
			   acc.count, tests[i].ewma, tests[i].count);
		errors++;
	}

	return errors ? -1 : 0;
}


static int wifi_stats_acc_tests(void)
{
	static const struct {
		int count;
		double num[4];
		double denom[4];
		double pct;
		double frames;
	} tests[] = {
		/* (25 - 10) / (300 - 100) */
		{ 3, { 10, 12, 25 }, { 100, 180, 300 }, 7.5, 200 },
		/*
		 * Both counters restart at the third sample, which becomes
		 * the baseline: (15 - 5) / (90 - 40)
		 */
		{ 4, { 10, 30, 5, 15 }, { 100, 200, 40, 90 }, 20.0, 50 },
		/* no frame sent: no ratio rather than a division by zero */
		{ 3, { 7, 7, 7 }, { 50, 50, 50 }, 0.0, 0 },
		{ 2, { 0, 3 }, { 50, 50 }, 0.0, 0 },
		/* one sample has no delta */
		{ 1, { 7 }, { 50 }, 0.0, 0 },
		/*
		 * Only the base restarts, at the third sample: (40 - 30) /
		 * (250 - 150)
		 */
		{ 4, { 10, 20, 30, 40 }, { 100, 200, 150, 250 }, 10.0, 100 },
		/*
		 * Only the counter restarts, at the third sample: (15 - 5) /
		 * (400 - 300)
		 */
		{ 4, { 10, 30, 5, 15 }, { 100, 200, 300, 400 }, 10.0, 100 },
	};
	struct wifi_stats_accum acc;
	struct os_reltime ts;
	double pct, frames;
	size_t i;
	int j, errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats ACC tests");

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		os_memset(&acc, 0, sizeof(acc));
		for (j = 0; j < tests[i].count; j++) {
			ts.sec = 1000 + j;
			ts.usec = 0;
			wifi_stats_accum_update(&acc, tests[i].num[j],
						tests[i].denom[j], &ts, 5);
		}
		pct = wifi_stats_accum_value(&acc, WIFI_STATS_AGG_ACC);
		frames = acc.last_base - acc.first_base;
		if (wifi_stats_test_equal(pct, tests[i].pct) &&
		    wifi_stats_test_equal(frames, tests[i].frames))
			continue;
		wpa_printf(MSG_ERROR,
			   "wifi_stats: ACC %d: %.9f%% of %.0f, expected %.9f%% of %.0f",
			   (int) i, pct, frames, tests[i].pct,
			   tests[i].frames);
		errors++;
	}

	return errors ? -1 : 0;
}


static int wifi_stats_test_pct(struct wifi_stats_ctx *ctx,
			       enum wifi_stats_metric_type metric,
			       const struct wifi_stats_agg_result *res,
			       const struct wifi_stats_sample *latest,
			       const char *expected)
{
	char buf[64], *pos = buf;

	buf[0] = '\0';
	if (wifi_stats_emit_pct(&pos, buf + sizeof(buf), metric, res, latest,
				ctx) < 0)
		return 1;
	return wifi_stats_test_str(buf, expected);
}


static int wifi_stats_pct_tests(struct wifi_stats_ctx *ctx)
{
	/* a ratio over fewer than 20 frames is not reported; PCT is 0-100 */
	static const struct {
		double pct;
		double frames;
		const char *expected;
	} acc_tests[] = {
		{ 5.0, 19, "" },
		{ 5.0, 20, " FrameLoss:5(ACC 10S)" },
		{ 250.0, 40, " FrameLoss:100(ACC 10S)" },
		{ -3.0, 40, " FrameLoss:0(ACC 10S)" },
	};
	/*
	 * Without aggregation the ratio is taken over the counters since
	 * association: failed / packets and retries / (packets + retries)
	 */
	static const struct {
		unsigned long packets, retries, failed;
		const char *loss;
		const char *retry;
	} base_tests[] = {
		/* 8 / 80 and 20 / (80 + 20) */
		{ 80, 20, 8, " FrameLoss:10", " FrameRetry:20" },
		/* 15 frames for loss, 5 / (15 + 5) for retry */
		{ 15, 5, 0, "", " FrameRetry:25" },
		{ 19, 0, 1, "", "" },
		/* 1 / 20 and 0 / 20 */
		{ 20, 0, 1, " FrameLoss:5", " FrameRetry:0" },
	};
	struct wifi_stats_agg_result res;
	struct wifi_stats_sample latest;
	size_t i;
	int errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats percentage tests");

	os_memset(&latest, 0, sizeof(latest));
	os_memset(&res, 0, sizeof(res));
	res.algorithm = WIFI_STATS_AGG_ACC;
	res.actual_points = 2;
	os_strlcpy(res.timeframe_str, "10S", sizeof(res.timeframe_str));

	for (i = 0; i < ARRAY_SIZE(acc_tests); i++) {
		res.value = acc_tests[i].pct;
		res.base_delta = acc_tests[i].frames;
		errors += wifi_stats_test_pct(ctx, WIFI_STATS_METRIC_FRAME_LOSS,
					      &res, &latest,
					      acc_tests[i].expected);
	}

	os_memset(&res, 0, sizeof(res));
	res.algorithm = WIFI_STATS_AGG_NONE;
	for (i = 0; i < ARRAY_SIZE(base_tests); i++) {
		latest.tx_packets = base_tests[i].packets;
		latest.tx_retry_count = base_tests[i].retries;
		latest.tx_retry_failed = base_tests[i].failed;
		errors += wifi_stats_test_pct(ctx, WIFI_STATS_METRIC_FRAME_LOSS,
					      &res, &latest,
					      base_tests[i].loss);
		errors += wifi_stats_test_pct(ctx,
					      WIFI_STATS_METRIC_FRAME_RETRY,
					      &res, &latest,
					      base_tests[i].retry);
	}

	return errors ? -1 : 0;
}


static int wifi_stats_timeframe_tests(void)
{
	/*
	 * WINDOW has three digits and a unit of seconds or minutes. A span
	 * can be bounded (0 for no bound): what is emitted, read in its own
	 * unit, is then never longer than the bound.
	 */
	static const struct {
		struct os_reltime span[2];
		unsigned int max_seconds;
		const char *expected;
	} tests[] = {
		{ { { 100, 0 }, { 110, 0 } }, 0, "10S" },
		/* 9.2 s */
		{ { { 100, 900000 }, { 110, 100000 } }, 0, "9S" },
		{ { { 100, 0 }, { 110, 499999 } }, 0, "10S" },
		{ { { 100, 0 }, { 110, 500000 } }, 0, "11S" },
		{ { { 100, 0 }, { 1099, 0 } }, 0, "999S" },
		{ { { 100, 0 }, { 1099, 499999 } }, 0, "999S" },
		/* 999.5 s rounds to 1000 s, which is 16.67 min */
		{ { { 100, 0 }, { 1099, 500000 } }, 0, "17M" },
		{ { { 100, 0 }, { 1100, 0 } }, 0, "17M" },
		/* 17.48 min and 17.5 min */
		{ { { 100, 0 }, { 1149, 0 } }, 0, "17M" },
		{ { { 100, 0 }, { 1150, 0 } }, 0, "18M" },
		{ { { 100, 0 }, { 60040, 0 } }, 0, "999M" },
		{ { { 100, 0 }, { 100100, 0 } }, 0, "999M" },
		/* 60.6 s of samples admitted to a 60 s window */
		{ { { 100, 0 }, { 160, 600000 } }, 60, "60S" },
		{ { { 100, 0 }, { 159, 0 } }, 60, "59S" },
		{ { { 100, 0 }, { 103, 0 } }, 2, "2S" },
		/* never 0S: 0.2 s is 1S with or without a bound */
		{ { { 100, 0 }, { 100, 200000 } }, 60, "1S" },
		/* 999.5 s rounds to 1000 s; bounded to 999 s: no minutes */
		{ { { 100, 0 }, { 1099, 500000 } }, 999, "999S" },
		/* 1206 s and 1235 s (20.6 min) bounded to 1200 s */
		{ { { 100, 0 }, { 1306, 0 } }, 1200, "20M" },
		{ { { 100, 0 }, { 1335, 0 } }, 1200, "20M" },
		/* 1019 s is 16.98 min and 17M is the bound itself */
		{ { { 100, 0 }, { 1119, 0 } }, 1020, "17M" },
		/* 1010 s is 16.83 min, but 17M reads 1020 s: above the bound */
		{ { { 100, 0 }, { 1110, 0 } }, 1010, "16M" },
		/* 1230 s is 20.5 min: 21M reads 1260 s */
		{ { { 100, 0 }, { 1330, 600000 } }, 1230, "20M" },
		{ { { 100, 0 }, { 3706, 0 } }, 3600, "60M" },
	};
	char buf[16];
	size_t i;
	int errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats timeframe tests");

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		wifi_stats_timeframe_str(buf, sizeof(buf), tests[i].span, 2,
					 tests[i].max_seconds);
		errors += wifi_stats_test_str(buf, tests[i].expected);
	}

	return errors ? -1 : 0;
}


enum wifi_stats_test_phy {
	WIFI_STATS_TEST_HT,
	WIFI_STATS_TEST_VHT,
	WIFI_STATS_TEST_HE,
	WIFI_STATS_TEST_EHT,
};


static int wifi_stats_maxspeed_tests(void)
{
	/*
	 * SC * MD * CR * SS / (SYM + GD) for one stream at the top MCS and the
	 * shortest guard interval, which is what a BSS without hardware
	 * capability information reports.
	 */
	static const struct {
		enum wifi_stats_test_phy phy;
		enum oper_chan_width width;
		const char *expected;
	} tests[] = {
		/* MCS 7: 52 * 6 * 5/6 / (3.2 + 0.4) */
		{ WIFI_STATS_TEST_HT, CONF_OPER_CHWIDTH_USE_HT, "72.22" },
		/* MCS 9: 234 * 8 * 5/6 / (3.2 + 0.4) */
		{ WIFI_STATS_TEST_VHT, CONF_OPER_CHWIDTH_80MHZ, "433.33" },
		/*
		 * MCS 9 is not valid for one stream at 20 MHz;
		 * MCS 8: 52 * 8 * 3/4 / (3.2 + 0.4)
		 */
		{ WIFI_STATS_TEST_VHT, CONF_OPER_CHWIDTH_USE_HT, "86.67" },
#ifdef CONFIG_IEEE80211AX
		/* MCS 11: 468 * 10 * 5/6 / (12.8 + 0.8) */
		{ WIFI_STATS_TEST_HE, CONF_OPER_CHWIDTH_40MHZ_6GHZ, "286.76" },
		/* MCS 11: 980 * 10 * 5/6 / (12.8 + 0.8) */
		{ WIFI_STATS_TEST_HE, CONF_OPER_CHWIDTH_80MHZ, "600.49" },
		/* MCS 11: 1960 * 10 * 5/6 / (12.8 + 0.8) */
		{ WIFI_STATS_TEST_HE, CONF_OPER_CHWIDTH_160MHZ, "1200.98" },
#endif /* CONFIG_IEEE80211AX */
#ifdef CONFIG_IEEE80211BE
		/* MCS 13: 3920 * 12 * 5/6 / (12.8 + 0.8) */
		{ WIFI_STATS_TEST_EHT, CONF_OPER_CHWIDTH_320MHZ, "2882.35" },
#endif /* CONFIG_IEEE80211BE */
	};
	static const struct {
		double mbps;
		const char *expected;
	} clamp_tests[] = {
		{ 2882.35, "2882.35" },
		{ 99999.99, "99999.99" },
		{ 100000.0, "99999.99" },
		{ 1234567.0, "99999.99" },
		{ -1.0, "0.00" },
	};
	struct hostapd_data *hapd;
	struct hostapd_config *conf;
	struct hostapd_bss_config *bss;
	char buf[32];
	size_t i;
	int errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats MAXSPEED tests");

	hapd = os_zalloc(sizeof(*hapd));
	conf = os_zalloc(sizeof(*conf));
	bss = os_zalloc(sizeof(*bss));
	if (!hapd || !conf || !bss) {
		os_free(hapd);
		os_free(conf);
		os_free(bss);
		return -1;
	}
	hapd->iconf = conf;
	hapd->conf = bss;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		conf->ieee80211n = 1;
		conf->ieee80211ac = tests[i].phy >= WIFI_STATS_TEST_VHT;
		conf->ieee80211ax = tests[i].phy >= WIFI_STATS_TEST_HE;
		conf->ieee80211be = tests[i].phy >= WIFI_STATS_TEST_EHT;
		conf->vht_oper_chwidth = tests[i].width;
#ifdef CONFIG_IEEE80211AX
		conf->he_oper_chwidth = tests[i].width;
#endif /* CONFIG_IEEE80211AX */
#ifdef CONFIG_IEEE80211BE
		conf->eht_oper_chwidth = tests[i].width;
#endif /* CONFIG_IEEE80211BE */
		os_snprintf(buf, sizeof(buf), "%.2f",
			    wifi_stats_bss_maxspeed(hapd));
		errors += wifi_stats_test_str(buf, tests[i].expected);
	}

	os_free(hapd);
	os_free(conf);
	os_free(bss);

	for (i = 0; i < ARRAY_SIZE(clamp_tests); i++) {
		os_snprintf(buf, sizeof(buf), "%.2f",
			    wifi_stats_clamp_maxspeed(clamp_tests[i].mbps));
		errors += wifi_stats_test_str(buf, clamp_tests[i].expected);
	}

	return errors ? -1 : 0;
}


static int wifi_stats_clamp_tests(struct wifi_stats_ctx *ctx)
{
	/* driver rates are in kbps; RATE has five digits and one decimal */
	static const struct {
		unsigned long kbps;
		const char *expected;
	} rate_tests[] = {
		{ 150000, " TxBitRate:150.0" },
		{ 99999900, " TxBitRate:99999.9" },
		{ 99999990, " TxBitRate:99999.9" },
		{ 200000000, " TxBitRate:99999.9" },
	};
	/*
	 * nl80211 delivers the signal as a signed octet, so nothing below -128
	 * is a measurement. The sign of SS carries no information: a positive
	 * value would read as the negative one.
	 */
	static const struct {
		int dbm;
		const char *expected;
	} rssi_tests[] = {
		{ -65, " RSSI:-65" },
		{ -128, " RSSI:-128" },
		{ -129, " RSSI:-128" },
		{ -32768, " RSSI:-128" },
		{ 5, "" },
	};
	struct wifi_stats_agg_result res;
	struct wifi_stats_sample latest;
	char buf[64], *pos;
	size_t i;
	int errors = 0;

	wpa_printf(MSG_INFO, "wifi_stats clamp tests");

	os_memset(&res, 0, sizeof(res));
	res.algorithm = WIFI_STATS_AGG_NONE;
	os_memset(&latest, 0, sizeof(latest));

	for (i = 0; i < ARRAY_SIZE(rate_tests); i++) {
		latest.current_tx_rate = rate_tests[i].kbps;
		pos = buf;
		buf[0] = '\0';
		if (wifi_stats_emit_bitrate(&pos, buf + sizeof(buf),
					    WIFI_STATS_METRIC_TX_BITRATE, &res,
					    &latest, ctx) < 0)
			errors++;
		errors += wifi_stats_test_str(buf, rate_tests[i].expected);
	}

	for (i = 0; i < ARRAY_SIZE(rssi_tests); i++) {
		latest.signal = rssi_tests[i].dbm;
		pos = buf;
		buf[0] = '\0';
		if (wifi_stats_emit_rssi(&pos, buf + sizeof(buf), &res,
					 &latest, ctx) < 0)
			errors++;
		errors += wifi_stats_test_str(buf, rssi_tests[i].expected);
	}

	return errors ? -1 : 0;
}


int wifi_stats_module_tests(void)
{
	struct hostapd_config *conf;
	struct hostapd_iface *iface;
	struct wifi_stats_ctx *ctx;
	int ret = 0;

	wpa_printf(MSG_INFO, "wifi_stats module tests");

	iface = os_zalloc(sizeof(*iface));
	conf = os_zalloc(sizeof(*conf));
	if (!iface || !conf) {
		os_free(iface);
		os_free(conf);
		return -1;
	}
	conf->wifi_stats_interval = WIFI_STATS_DEFAULT_INTERVAL;
	conf->wifi_stats_wba_window = WIFI_STATS_DEFAULT_WINDOW;
	conf->wifi_stats_ewma_weight = WIFI_STATS_DEFAULT_EWMA_WEIGHT;
	conf->wifi_stats_span = WIFI_STATS_SPAN_WINDOW;
	iface->conf = conf;
	wifi_stats_init(iface);
	ctx = iface->wifi_stats;
	if (!ctx) {
		os_free(iface);
		os_free(conf);
		return -1;
	}

	if (wifi_stats_aggregation_tests() < 0 ||
	    wifi_stats_hold_tests() < 0 ||
	    wifi_stats_acc_tests() < 0 ||
	    wifi_stats_pct_tests(ctx) < 0 ||
	    wifi_stats_timeframe_tests() < 0 ||
	    wifi_stats_maxspeed_tests() < 0 ||
	    wifi_stats_clamp_tests(ctx) < 0)
		ret = -1;

	wifi_stats_deinit(iface);
	os_free(iface);
	os_free(conf);

	return ret;
}
