/*
 * hostapd module tests
 * Copyright (c) 2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/module_tests.h"

int hapd_module_tests(void)
{
	int ret = 0;

	wpa_printf(MSG_INFO, "hostapd module tests");

#ifdef CONFIG_WIFI_STATS
	if (wifi_stats_module_tests() < 0)
		ret = -1;
#endif /* CONFIG_WIFI_STATS */

	return ret;
}
