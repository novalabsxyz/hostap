# WBA Connect-Info (wifi_stats) tests, draft-ietf-radext-connectinfo-02
# Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import select
import threading
import time

import hostapd
import hwsim_utils
from utils import *
from hwsim import HWSimRadio
from wpasupplicant import WpaSupplicant
from test_eht import eht_mld_ap_wpa2_params
from connectinfo_abnf import parse, is_valid, ConnectInfoError

SSID = "wifi-stats"
PASSPHRASE = "12345678"

# mac80211_hwsim reports no TX retries without wmediumd, so FrameLoss and
# FrameRetry are checked for form only. Only samples with new frames are
# aggregated, so tests expecting an aggregate keep traffic flowing.

def probe_wifi_stats(hapd):
    # Decided before any wifi_stats_* parameter is set: a hostapd built
    # without the feature does not know the command, while one that has it
    # answers FAIL until the interface is enabled (there is no context yet).
    if "UNKNOWN COMMAND" in hapd.request("WIFI_STATS_STATUS"):
        raise HwsimSkip("wifi_stats not supported in the build")

def check_wifi_stats(hapd):
    # After ENABLE every build that passed the probe has a context.
    res = hapd.request("WIFI_STATS_STATUS")
    if "UNKNOWN COMMAND" in res or res.startswith("FAIL"):
        raise Exception("WIFI_STATS_STATUS failed on an enabled interface: "
                        "%s" % res.strip())
    return res

def split_wifi_stats(params):
    plain = {}
    stats = {}
    for key, value in params.items():
        (stats if key.startswith("wifi_stats_") else plain)[key] = value
    return plain, stats

def set_wifi_stats(hapd, stats):
    for key, value in stats.items():
        for val in (value if isinstance(value, list) else [value]):
            hapd.set(key, val)

def add_ap(apdev, params, wait_enabled=True, timeout=30):
    # hostapd.add_ap() with the probe in between: the wifi_stats_* parameters
    # are only set once the build is known to have the feature, so a build
    # without it skips instead of failing on the first SET.
    plain, stats = split_wifi_stats(params)
    hapd = hostapd.add_ap(apdev, plain, no_enable=True)
    probe_wifi_stats(hapd)
    set_wifi_stats(hapd, stats)
    hapd.enable()
    if wait_enabled:
        ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=timeout)
        if ev is None:
            raise Exception("AP startup timed out")
        if "AP-ENABLED" not in ev:
            raise Exception("AP startup failed")
    return hapd

def start_ap(apdev, extra=None, ssid=SSID, wba_enabled="1", **kwargs):
    # No country_code here: run-tests.py fails any test that leaves it set.
    # Only the 5 GHz cases set it, and they pair it with clear_regdom().
    params = hostapd.wpa2_params(ssid=ssid, passphrase=PASSPHRASE)
    # Collection and the WBA format are opt-in; wba_enabled=None leaves the
    # directive out, for the tests of the default.
    if wba_enabled is not None:
        params["wifi_stats_wba_enabled"] = wba_enabled
    if extra:
        params.update(extra)
    hapd = add_ap(apdev, params, **kwargs)
    check_wifi_stats(hapd)
    return hapd

def connect_sta(dev, hapd, ssid=SSID, freq="2412"):
    dev.connect(ssid, psk=PASSPHRASE, scan_freq=freq)
    hapd.wait_sta()
    return dev.own_addr()

def rejected(res):
    # The ctrl_iface matches on the "CMD " prefix including the space, so a
    # missing argument yields UNKNOWN COMMAND rather than FAIL.
    return res.startswith("FAIL") or "UNKNOWN COMMAND" in res

def set_rejected(hapd, key, value):
    # hostapd.py set() raises on FAIL; a value expected to be refused is sent
    # directly. An empty value leaves "SET <key>", which has no value at all.
    cmd = ("SET %s %s" % (key, value)).strip()
    return hapd.request(cmd).startswith("FAIL")

def conn_info_raw(hapd, addr):
    res = hapd.request("WIFI_STATS_CONNECT_INFO " + addr)
    if res.startswith("FAIL"):
        raise Exception("WIFI_STATS_CONNECT_INFO failed for %s" % addr)
    return res.strip()

def conn_info(hapd, addr, allow_extensibility=False):
    text = conn_info_raw(hapd, addr)
    try:
        return parse(text, allow_extensibility=allow_extensibility)
    except ConnectInfoError as e:
        raise Exception("Connect-Info does not conform: %s" % e)

def wifi_stats_status(hapd):
    # Every AP here was enabled after the build probe passed, so a failure
    # now is a defect and not a build without the feature.
    res = hapd.request("WIFI_STATS_STATUS")
    if "UNKNOWN COMMAND" in res or res.startswith("FAIL"):
        raise Exception("WIFI_STATS_STATUS failed: %s" % res.strip())
    out = {}
    for line in res.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out

def span_seconds(span):
    # None for the AVG-EXP weight form, which is not a duration.
    if span is None or span[-1] not in "SM":
        return None
    return int(span[:-1]) * (60 if span[-1] == 'M' else 1)

def drive_traffic(dev, hapd, count=3):
    # Frames in both directions refresh the AP's per-station signal and rates.
    for i in range(count):
        hwsim_utils.test_connectivity(dev, hapd)

def drive_traffic_for(dev, hapds, seconds, pause=0.3):
    # Spread traffic over several collection intervals so that more than one
    # sample is fresh. pause=0 sends as many frames as possible, for the loss
    # and retry ratios.
    if not isinstance(hapds, (list, tuple)):
        hapds = [hapds]
    end = time.time() + seconds
    while True:
        for hapd in hapds:
            hwsim_utils.test_connectivity(dev, hapd)
        if time.time() >= end:
            break
        time.sleep(pause)

def set_sta_rssi(dev, hapd, value):
    # Make the AP perceive value dBm for this station. Range is -50..-30.
    try:
        hwsim_utils.set_rx_rssi(dev, value)
    except Exception:
        raise HwsimSkip("set_rx_rssi not supported")
    drive_traffic(dev, hapd)

def test_wifi_stats_grammar_strict(dev, apdev):
    """wifi_stats Connect-Info syntax with different PHY configurations"""
    configs = [
        ("11g 2.4GHz", {"hw_mode": "g", "channel": "1"}, "2412", False),
        ("11n HT40+", {"hw_mode": "g", "channel": "1", "ieee80211n": "1",
                       "ht_capab": "[HT40+]"}, "2412", False),
        ("11a 5GHz", {"hw_mode": "a", "channel": "36",
                      "country_code": "FI"}, "5180", True),
        ("11ac VHT80", {"hw_mode": "a", "channel": "36", "country_code": "FI",
                        "ieee80211n": "1", "ieee80211ac": "1",
                        "ht_capab": "[HT40+]", "vht_oper_chwidth": "1",
                        "vht_oper_centr_freq_seg0_idx": "42"}, "5180", True),
        ("11ax HE80", {"hw_mode": "a", "channel": "36", "country_code": "FI",
                       "ieee80211n": "1", "ieee80211ac": "1",
                       "ieee80211ax": "1", "ht_capab": "[HT40+]",
                       "vht_oper_chwidth": "1",
                       "vht_oper_centr_freq_seg0_idx": "42",
                       "he_oper_chwidth": "1",
                       "he_oper_centr_freq_seg0_idx": "42"}, "5180", True),
    ]
    for name, extra, freq, regdom in configs:
        hapd = None
        try:
            hapd = start_ap(apdev[0], extra)
            addr = connect_sta(dev[0], hapd, freq=freq)
            time.sleep(2)
            drive_traffic(dev[0], hapd)
            text = conn_info_raw(hapd, addr)
            logger.info("%s: %s" % (name, text))
            ci = parse(text)
            if ci.count("Channel") > 1:
                raise Exception("%s: Channel repeated" % name)
        finally:
            if regdom:
                clear_regdom(hapd, dev)
            elif hapd:
                dev[0].request("DISCONNECT")
                dev[0].wait_disconnected()
                hapd.disable()
            dev[0].dump_monitor()

def legacy_block(dev, hapd, freq="2412"):
    addr = connect_sta(dev, hapd, freq=freq)
    text = conn_info_raw(hapd, addr)
    ci = parse(text)
    # legacyAttributes is a single production: neither half may appear alone.
    if (ci.maxspeed is None) != (ci.amendment is None):
        raise Exception("MAXSPEED and WIFIAMENDMENT are not atomic: %s" % text)
    if ci.maxspeed is None:
        raise Exception("No rate reported at all: %s" % text)
    # The parse enforces the two fractional digits; assert the text too so a
    # regression fails with a readable message rather than a parse error.
    frac = text.split(" Mbps")[0].rsplit(".", 1)[1]
    if len(frac) != 2:
        raise Exception("MAXSPEED must carry exactly two fractional digits, "
                        "got %r in %r" % (frac, text))
    dev.request("DISCONNECT")
    dev.wait_disconnected()
    dev.dump_monitor()
    hapd.disable()
    return ci, text

def test_wifi_stats_legacy_attribute_block(dev, apdev):
    """wifi_stats Connect-Info MAXSPEED and amendment of the BSS"""
    # MAXSPEED is SC * MD * CR * SS / (SYM + GD) for the BSS. Without HT it
    # is exact: 11b is the DSSS/CCK constant, 11g is 48 * 6 * 3/4 / 4.
    for extra, want in [({"hw_mode": "b", "ieee80211n": "0"},
                         (11.0, "b")),
                        ({"hw_mode": "g", "ieee80211n": "0"},
                         (54.0, "g"))]:
        ci, text = legacy_block(dev[0], start_ap(apdev[0], extra))
        if (ci.maxspeed, ci.amendment) != want:
            raise Exception("Expected %.2f Mbps 802.11%s, got %s" %
                            (want[0], want[1], text))

    # With HT the stream count is not pinned; HT40/HT20 is 108/52 subcarriers.
    ht20, text20 = legacy_block(dev[0], start_ap(apdev[0], {}))
    ht40, text40 = legacy_block(dev[0], start_ap(
        apdev[0], {"ht_capab": "[HT40+]"}))
    if ht20.amendment != "n" or ht40.amendment != "n":
        raise Exception("HT BSS not reported as 802.11n: %s / %s" %
                        (text20, text40))
    if abs(ht40.maxspeed / ht20.maxspeed - 108.0 / 52.0) > 0.001:
        raise Exception("HT40/HT20 MAXSPEED ratio %.4f is not 108/52: "
                        "%s / %s" % (ht40.maxspeed / ht20.maxspeed,
                                     text20, text40))

def test_wifi_stats_maxspeed_network_level(dev, apdev):
    """wifi_stats MAXSPEED and amendment with HT and non-HT stations"""
    # Draft section 2: these are "not uniquely associated with a single IEEE
    # 802.11 connection". A legacy client on an HT BSS must see the same.
    hapd = start_ap(apdev[0])
    full = connect_sta(dev[0], hapd)
    dev[1].connect(SSID, psk=PASSPHRASE, scan_freq="2412", disable_ht="1")
    hapd.wait_sta()
    legacy = dev[1].own_addr()
    drive_traffic(dev[0], hapd)
    drive_traffic(dev[1], hapd)
    a = conn_info(hapd, full)
    b = conn_info(hapd, legacy)
    if (a.maxspeed, a.amendment) != (b.maxspeed, b.amendment):
        raise Exception("HT and non-HT stations report different legacy "
                        "blocks: %s / %s" % (a.text, b.text))
    if a.amendment != "n":
        raise Exception("An HT BSS reported 802.11%s" % a.amendment)

def test_wifi_stats_channel_and_op_class(dev, apdev):
    """wifi_stats Connect-Info Channel and Global-OC"""
    # Global operating classes per IEEE Std 802.11, Annex E. The draft does
    # not say which channel of a wide BSS is reported, so both the primary
    # and the center channel are accepted.
    cases = [
        ("2.4GHz ch1 20MHz", {"hw_mode": "g", "channel": "1"}, "2412",
         [1], [81], False),
        ("2.4GHz ch1 HT40+", {"hw_mode": "g", "channel": "1",
                              "ieee80211n": "1", "ht_capab": "[HT40+]"},
         "2412", [1, 3], [83], False),
        ("5GHz ch36 VHT80", {"hw_mode": "a", "channel": "36",
                             "country_code": "FI", "ieee80211n": "1",
                             "ieee80211ac": "1", "ht_capab": "[HT40+]",
                             "vht_oper_chwidth": "1",
                             "vht_oper_centr_freq_seg0_idx": "42"},
         "5180", [36, 42], [128], True),
    ]
    for name, extra, freq, expect_chan, expect_goc, regdom in cases:
        hapd = None
        try:
            hapd = start_ap(apdev[0], extra)
            addr = connect_sta(dev[0], hapd, freq=freq)
            time.sleep(2)
            ci = conn_info(hapd, addr)

            if ci.channel is None:
                raise Exception("%s: no Channel reported" % name)
            if ci.channel not in expect_chan:
                raise Exception("%s: Channel %d is neither the primary nor "
                                "the center channel of the BSS %r" %
                                (name, ci.channel, expect_chan))

            goc = ci.get("Global-OC")
            if goc is None:
                raise Exception("%s: no Global-OC reported" % name)
            if int(goc.value) not in expect_goc:
                raise Exception("%s: Global-OC %s is not the expected %r" %
                                (name, goc.value, expect_goc))
            # Global-OC's production carries no ["(" AGGR ")"] option.
            if goc.algo is not None:
                raise Exception("%s: Global-OC must not carry an "
                                "aggregation suffix" % name)
            if goc.link_id is not None:
                raise Exception("%s: Link-ID on a non-MLO station" % name)
        finally:
            if regdom:
                clear_regdom(hapd, dev)
            elif hapd:
                dev[0].request("DISCONNECT")
                dev[0].wait_disconnected()
                hapd.disable()
            dev[0].dump_monitor()

def test_wifi_stats_rate_unit(dev, apdev):
    """wifi_stats Connect-Info bit rate unit"""
    hapd = start_ap(apdev[0], {"hw_mode": "g", "channel": "1",
                               "ieee80211n": "1"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)
    drive_traffic(dev[0], hapd)
    ci = conn_info(hapd, addr)

    # The BSS's MAXSPEED bounds every rate (144.44 for hwsim's HT20 2SS); a
    # kbps or 100 kbps scaling error lands 10x or 100x above it. Rates are
    # rounded to 0.1 Mbps, so one may exceed the exact maximum by 0.05.
    for key in ["RxBitRate", "TxBitRate"]:
        a = ci.get(key)
        if a is None:
            raise Exception("No %s reported" % key)
        value = float(a.value)
        if not 0.0 < value <= ci.maxspeed + 0.05:
            raise Exception("%s %r Mbps exceeds the BSS maximum %.2f" %
                            (key, value, ci.maxspeed))
        # RATE permits at most one fractional digit.
        if '.' in a.value and len(a.value.split('.')[1]) != 1:
            raise Exception("RATE must carry at most one fractional digit: "
                            "%r" % a.value)

def test_wifi_stats_rssi_form(dev, apdev):
    """wifi_stats Connect-Info RSSI format and value"""
    hapd = start_ap(apdev[0])
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)
    drive_traffic(dev[0], hapd)

    signs = set()
    for i in range(5):
        ci = conn_info(hapd, addr)
        rssi = ci.get("RSSI")
        if rssi is None:
            raise Exception("No RSSI reported")
        signs.add(rssi.value.startswith('-'))
        time.sleep(0.3)
    # The draft blesses both conventions, so assert consistency, not a sign.
    if len(signs) != 1:
        raise Exception("RSSI sign convention is not consistent")

    sta = hapd.get_sta(addr)
    if 'signal' in sta:
        driver = abs(int(sta['signal']))
        reported = abs(int(ci.get("RSSI").value))
        if abs(driver - reported) > 10:
            raise Exception("RSSI %d differs from the driver's %d by more "
                            "than 10 dB" % (reported, driver))

def test_wifi_stats_percentage_form(dev, apdev):
    """wifi_stats Connect-Info FrameLoss and FrameRetry format"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "5",
                               "wifi_stats_span": "window"})
    addr = connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 6, pause=0)
    ci = conn_info(hapd, addr)

    # No non-zero assertion; see the note at the top of this file. Both are
    # expected here: ACC is the default and there has been time to aggregate.
    for key in ["FrameLoss", "FrameRetry"]:
        a = ci.get(key)
        if a is None:
            raise Exception("%s missing with the ACC default and 6 s of "
                            "dwell" % key)
        if not a.value.isdigit() or not 0 <= int(a.value) <= 100:
            raise Exception("%s %r is outside PCT (0-100)" % (key, a.value))
        if len(a.value) > 1 and a.value[0] == '0':
            raise Exception("%s %r has a leading zero" % (key, a.value))

def test_wifi_stats_attribute_length(dev, apdev):
    """wifi_stats Connect-Info attribute length"""
    hapd = None
    try:
        hapd = start_ap(apdev[0], {
            "hw_mode": "a", "channel": "36", "country_code": "FI",
            "ieee80211n": "1", "ieee80211ac": "1", "ht_capab": "[HT40+]",
            "vht_oper_chwidth": "1", "vht_oper_centr_freq_seg0_idx": "42",
            "wifi_stats_interval": "1",
            "wifi_stats_wba_window": "3600",
            "wifi_stats_span": "window",
            "wifi_stats_ewma_weight": "9",
            "wifi_stats_metric_rssi": "AVG-EXP",
        })
        addr = connect_sta(dev[0], hapd, freq="5180")
        drive_traffic_for(dev[0], hapd, 3)
        text = conn_info_raw(hapd, addr)
        logger.info("max verbosity: %d octets: %s" %
                    (len(text.encode()), text))
        # Only an MLO attribute with several links can approach the limit;
        # this checks that a single BSS with the longest fields stays below.
        if len(text.encode()) > 253:
            raise Exception("Connect-Info is %d octets, over the RADIUS "
                            "limit" % len(text.encode()))
        parse(text)
    finally:
        clear_regdom(hapd, dev)
        dev[0].dump_monitor()

def test_wifi_stats_no_extensibility_reliance(dev, apdev):
    """wifi_stats Connect-Info without the ABNF extensibility rule"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "3",
                               "wifi_stats_span": "window"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(4)
    drive_traffic(dev[0], hapd)
    text = conn_info_raw(hapd, addr)

    ci = parse(text, allow_extensibility=True)
    if ci.used_extensibility():
        raise Exception("Attribute(s) parsed only via the extensibility "
                        "production: %r in %r" %
                        (ci.used_extensibility(), text))

def test_wifi_stats_query_is_nondestructive(dev, apdev):
    """wifi_stats Connect-Info query not resetting the report span"""
    # A local read is not a RADIUS signal, so it must not reset the
    # report-mode accumulator. Every other test here relies on that.
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_span": "report",
                               "wifi_stats_metric_rssi": "AVG-LIN"})
    addr = connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 8)

    first = conn_info(hapd, addr).get("RSSI")
    time.sleep(0.2)
    second = conn_info(hapd, addr).get("RSSI")
    if first is None or first.span is None:
        raise Exception("No aggregated RSSI after 8 s of association")
    # An aggregated first read followed by a bare second read is itself the
    # reset: the accumulator dropped below two samples between the two calls.
    if second is None or second.span is None:
        raise Exception("Second read not aggregated after an aggregated "
                        "first read")

    s1 = span_seconds(first.span)
    if s1 is None:
        raise Exception("RSSI is not using a duration span despite "
                        "AVG-LIN being configured")
    s2 = span_seconds(second.span)
    if s2 is None:
        raise Exception("The span form changed between two reads 200 ms "
                        "apart: %r then %r" % (first.span, second.span))
    if s2 + 1 < s1:
        raise Exception("Span collapsed from %ds to %ds across two reads "
                        "200 ms apart" %
                        (s1, s2))

    # Fresh samples only fold while frames flow, so the span grows only
    # under traffic; one that stayed put or shrank means a reset.
    drive_traffic_for(dev[0], hapd, 5)
    third = conn_info(hapd, addr).get("RSSI")
    s3 = span_seconds(third.span) if third is not None else None
    if s3 is None:
        raise Exception("No aggregated RSSI after 5 more seconds of traffic")
    if s3 < s2 + 3:
        raise Exception("Span went from %ds to %ds over 5 s of traffic "
                        "while the station stayed associated" % (s2, s3))

def test_wifi_stats_algo_tokens(dev, apdev):
    """wifi_stats Connect-Info aggregation algorithm tokens"""
    for algo in ["MIN", "MAX", "AVG-LIN", "AVG-EXP"]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "4",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_metric_rssi": algo})
        try:
            addr = connect_sta(dev[0], hapd)
            drive_traffic_for(dev[0], hapd, 5)
            text = conn_info_raw(hapd, addr)
            ci = parse(text)
            rssi = ci.get("RSSI")
            if rssi is None or rssi.algo is None:
                raise Exception("%s: RSSI carries no aggregation suffix: %s" %
                                (algo, text))
            if rssi.algo != algo:
                raise Exception("Configured %s but emitted %s" %
                                (algo, rssi.algo))
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def test_wifi_stats_algo_values(dev, apdev):
    """wifi_stats RSSI aggregation with MIN, MAX and AVG-LIN"""
    # The endpoints of the set_rx_rssi() range separate the algorithms: MIN
    # and MAX land on them, AVG-LIN in between. Each level is held for 5 s
    # and the window covers both.
    levels = [-50, -30]
    expected = {"MIN": -50, "MAX": -30, "AVG-LIN": -40}
    tol = 4
    for algo in ["MIN", "MAX", "AVG-LIN"]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "30",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_metric_rssi": algo})
        try:
            addr = connect_sta(dev[0], hapd)
            for level in levels:
                set_sta_rssi(dev[0], hapd, level)
                drive_traffic_for(dev[0], hapd, 5)
            ci = conn_info(hapd, addr)
            rssi = ci.get("RSSI")
            if rssi is None or rssi.algo != algo:
                raise Exception("%s: no aggregated RSSI" % algo)
            got = abs(int(rssi.value))
            want = abs(expected[algo])
            if abs(got - want) > tol:
                raise Exception("%s over %r gave %d dBm, expected about %d" %
                                (algo, levels, -got, -want))
        finally:
            try:
                hwsim_utils.reset_rx_rssi(dev[0])
            except Exception:
                pass
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def test_wifi_stats_aggr_window_form(dev, apdev):
    """wifi_stats Connect-Info aggregation window format"""
    # The 4 s window is shorter than the traffic, so its bound is reached.
    for window in [1, 4, 30, 60]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": str(window),
                                   "wifi_stats_span": "window"})
        try:
            addr = connect_sta(dev[0], hapd)
            drive_traffic_for(dev[0], hapd, min(window, 5) + 2)
            text = conn_info_raw(hapd, addr)
            ci = parse(text)
            for a in ci.attrs:
                if a.span is None:
                    continue
                secs = span_seconds(a.span)
                if secs is None:
                    continue
                # The draft does not say whether WINDOW reports the
                # configured window or the observed span, so bound it only.
                if secs > window:
                    raise Exception("%s span %ds exceeds the configured "
                                    "window %ds" % (a.key, secs, window))
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def test_wifi_stats_window_digit_overflow(dev, apdev):
    """wifi_stats Connect-Info WINDOW with a window above 999 seconds"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "60",
                               "wifi_stats_span": "window"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(3)
    drive_traffic(dev[0], hapd)

    # The window can be set up to 3600 s, but WINDOW has at most three
    # digits. The conversion to minutes is covered by the hostapd module
    # tests.
    for window in [999, 1000, 1001, 3599, 3600]:
        hapd.set("wifi_stats_wba_window", str(window))
        # A window change restarts the statistics; 4 s of traffic give the
        # two fresh samples needed for a span.
        drive_traffic_for(dev[0], hapd, 4)
        text = conn_info_raw(hapd, addr)
        ci = parse(text)
        with_span = 0
        for a in ci.attrs:
            if a.span is None or a.span[-1] not in "SM":
                continue
            with_span += 1
            digits = a.span[:-1]
            if len(digits) > 3:
                raise Exception("window=%d produced a %d-digit WINDOW %r, "
                                "which no conforming parser accepts: %s" %
                                (window, len(digits), a.span, text))
        if not with_span:
            raise Exception("window=%d: no attribute carries a span after 4 s "
                            "of traffic, the digit check was not reached: %s" %
                            (window, text))

def test_wifi_stats_ewma_weight_form(dev, apdev):
    """wifi_stats Connect-Info AVG-EXP weight and sample period"""
    # SAMPLE has four digits: a 1-9 s interval in ms; 10 s is omitted.
    for weight, interval, sample in [(1, 1, "1000"), (5, 1, "1000"),
                                     (9, 1, "1000"), (5, 10, None)]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": str(interval),
                                   "wifi_stats_wba_window": "60",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_ewma_weight": str(weight),
                                   "wifi_stats_metric_rssi": "AVG-EXP",
                                   "wifi_stats_metric_txbitrate": "MAX"})
        try:
            addr = connect_sta(dev[0], hapd)
            # The first tick only sets the freshness baseline; two fresh
            # samples are needed, below which there is no AGGR.
            drive_traffic_for(dev[0], hapd, 3 * interval + 3)
            text = conn_info_raw(hapd, addr)
            ci = parse(text)

            rssi = ci.get("RSSI")
            if rssi is None or rssi.algo != "AVG-EXP":
                raise Exception("Weight %d: no AVG-EXP RSSI: %s" %
                                (weight, text))
            parts = rssi.span.split('-')
            if parts[0] != str(weight):
                raise Exception("Emitted weight %r, configured %d" %
                                (parts[0], weight))
            got = parts[1] if len(parts) > 1 else None
            if got != sample:
                raise Exception("Interval %ds: SAMPLE %r, expected %r: %s" %
                                (interval, got, sample, text))

            # The grammar does not bind the weight form to AVG-EXP; hostapd
            # uses it for AVG-EXP only. TxBitRate has to be present for this
            # to be checked.
            tx = ci.get("TxBitRate")
            if tx is None:
                raise Exception("Weight %d: no TxBitRate reported despite "
                                "driven traffic: %s" % (weight, text))
            if tx.algo != "MAX":
                raise Exception("Weight %d: TxBitRate emits %s, configured "
                                "MAX: %s" % (weight, tx.algo, text))
            if tx.span is not None and tx.span[-1] not in "SM":
                raise Exception("MAX emitted the weight form %r instead "
                                "of a WINDOW" % tx.span)
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def test_wifi_stats_none_omits_aggr(dev, apdev):
    """wifi_stats Connect-Info with all metrics set to NONE"""
    extra = {"wifi_stats_interval": "1", "wifi_stats_wba_window": "5",
             "wifi_stats_span": "window"}
    for m in ["rxbitrate", "txbitrate", "rssi", "frameloss", "frameretry"]:
        extra["wifi_stats_metric_" + m] = "NONE"
    hapd = start_ap(apdev[0], extra)
    addr = connect_sta(dev[0], hapd)
    time.sleep(6)
    drive_traffic(dev[0], hapd)
    text = conn_info_raw(hapd, addr)
    parse(text)
    if '(' in text or ')' in text:
        raise Exception("Instantaneous values must not carry an AGGR "
                        "definition: %s" % text)

def test_wifi_stats_acc_restricted(dev, apdev):
    """wifi_stats ACC algorithm rejected for RSSI and bit rates"""
    # Stricter than the draft, which restricts ACC only in an ABNF comment:
    # "RSSI:-40(ACC 60S)" is grammatical. This pins hostapd's config policy.
    hapd = start_ap(apdev[0])
    for metric in ["RSSI", "TxBitRate", "RxBitRate"]:
        before = wifi_stats_status(hapd)[metric]
        if not set_rejected(hapd, "wifi_stats_metric_" + metric.lower(),
                            "ACC"):
            raise Exception("ACC accepted for %s" % metric)
        after = wifi_stats_status(hapd)[metric]
        if before != after:
            raise Exception("%s changed from %r to %r on a rejected SET" %
                            (metric, before, after))

    for metric in ["FrameLoss", "FrameRetry"]:
        hapd.set("wifi_stats_metric_" + metric.lower(), "ACC")
        if wifi_stats_status(hapd)[metric] != "ACC":
            raise Exception("%s is not ACC after SET" % metric)

def test_wifi_stats_default_algorithms(dev, apdev):
    """wifi_stats default aggregation algorithms"""
    hapd = start_ap(apdev[0])
    status = wifi_stats_status(hapd)
    # Draft section 4.2
    if status.get("TxBitRate") != "MAX" or status.get("RxBitRate") != "MAX":
        raise Exception("Bit rates default to %r/%r, not MAX" %
                        (status.get("TxBitRate"), status.get("RxBitRate")))
    if status.get("RSSI") not in ["AVG-LIN", "AVG-EXP"]:
        raise Exception("RSSI defaults to %r, not an average" %
                        status.get("RSSI"))
    for m in ["FrameLoss", "FrameRetry"]:
        if status.get(m) != "ACC":
            raise Exception("%s defaults to %r, not ACC" % (m, status.get(m)))

    # STATUS alone does not prove the formatter honors the defaults.
    addr = connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 4)
    ci = conn_info(hapd, addr)

    tx = ci.get("TxBitRate")
    rx = ci.get("RxBitRate")
    rssi = ci.get("RSSI")
    if tx is None or rx is None or rssi is None:
        raise Exception("Bit rate or RSSI missing from the wire: %s" %
                        ci.text)
    if tx.algo != "MAX" or rx.algo != "MAX":
        raise Exception("Bit rates emit %r/%r on the wire, not MAX" %
                        (tx.algo, rx.algo))
    if rssi.algo not in ("AVG-LIN", "AVG-EXP"):
        raise Exception("RSSI emits %r on the wire, not an average" %
                        rssi.algo)
    for key in ["FrameLoss", "FrameRetry"]:
        a = ci.get(key)
        if a is not None and a.algo != "ACC":
            raise Exception("%s emits %r on the wire, not ACC" %
                            (key, a.algo))

ACCT_PORT = 18139
ACCT_SECRET = b"radius"

ACCT_START = 1
ACCT_STOP = 2
ACCT_INTERIM = 3

def acct_status_type(pkt):
    try:
        raw = pkt["Acct-Status-Type"][0]
    except (KeyError, IndexError):
        return None
    if isinstance(raw, int):
        return raw
    return {"Start": ACCT_START, "Stop": ACCT_STOP,
            "Interim-Update": ACCT_INTERIM}.get(str(raw))

def connect_info_of(pkt):
    try:
        value = pkt["Connect-Info"][0]
    except (KeyError, IndexError):
        return None
    if isinstance(value, bytes):
        return value.decode('utf-8')
    return str(value)

class AcctCapture(object):
    def __init__(self, port=ACCT_PORT):
        try:
            import pyrad.server
            import pyrad.packet
            import pyrad.dictionary
        except ImportError:
            raise HwsimSkip("No pyrad modules available")
        self._pyrad = pyrad
        self.packets = []
        self.stop = threading.Event()
        self.port = port
        capture = self.packets

        class Server(pyrad.server.Server):
            def HandleAcctPacket(self, pkt):
                capture.append(pkt)
                reply = self.CreateReplyPacket(pkt)
                self.SendReplyPacket(pkt.fd, reply)

            def RunWithStop(self, stop):
                self._poll = select.poll()
                self._fdmap = {}
                self._PrepareSockets()
                while not stop.is_set():
                    for (fd, event) in self._poll.poll(500):
                        if event != select.POLLIN:
                            continue
                        try:
                            self._ProcessInput(self._fdmap[fd])
                        except pyrad.server.ServerPacketError as err:
                            logger.info("acct server dropped packet: %s" % err)
                        except pyrad.packet.PacketError as err:
                            logger.info("acct server invalid packet: %s" % err)
                for fd in self.authfds + self.acctfds:
                    fd.close()

        self.srv = Server(dict=pyrad.dictionary.Dictionary("dictionary.radius"),
                          authport=18138, acctport=port)
        self.srv.hosts["127.0.0.1"] = pyrad.server.RemoteHost(
            "127.0.0.1", ACCT_SECRET, "localhost")
        self.srv.BindToAddress("127.0.0.1")

    def __enter__(self):
        self.thread = threading.Thread(target=self.srv.RunWithStop,
                                       args=(self.stop,))
        self.thread.daemon = True
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=5)

    def of_type(self, status_type):
        return [p for p in self.packets
                if acct_status_type(p) == status_type]

    def wait_for(self, status_type, count=1, timeout=30, tick=None):
        # tick runs on every poll, e.g. to keep traffic flowing
        end = time.time() + timeout
        while time.time() < end:
            got = self.of_type(status_type)
            if len(got) >= count:
                return got
            if tick:
                tick()
            time.sleep(0.3)
        raise Exception("Timed out waiting for %d accounting packets of type "
                        "%d (saw %d)" % (count, status_type,
                                         len(self.of_type(status_type))))

def acct_params(extra=None, interim=None):
    params = {"acct_server_addr": "127.0.0.1",
              "acct_server_port": str(ACCT_PORT),
              "acct_server_shared_secret": ACCT_SECRET.decode()}
    if interim is not None:
        params["radius_acct_interim_interval"] = str(interim)
    if extra:
        params.update(extra)
    return params

def test_wifi_stats_radius_accounting_start(dev, apdev):
    """wifi_stats Connect-Info in RADIUS Accounting-Request (Start)"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params({"wifi_stats_span": "report"}))
        connect_sta(dev[0], hapd)
        start = acct.wait_for(ACCT_START)[0]

        if len(start["Connect-Info"]) != 1:
            raise Exception("Expected exactly one Connect-Info, got %d" %
                            len(start["Connect-Info"]))
        text = connect_info_of(start)
        logger.info("Accounting-Start Connect-Info: %s" % text)
        ci = parse(text)
        if not [a for a in ci.attrs if a.kind == 'kv']:
            raise Exception("The WBA format did not engage: %s" % text)
        # Only EAPOL has flowed, at a basic rate: rates may be instantaneous
        # but not aggregated, and no ratio is reported over so few frames.
        for key in ["TxBitRate", "RxBitRate"]:
            a = ci.get(key)
            if a is not None and a.algo is not None:
                raise Exception("%s carries %s at Accounting-Start, before "
                                "any data: %s" % (key, a.algo, text))
        for key in ["FrameLoss", "FrameRetry"]:
            if ci.get(key) is not None:
                raise Exception("%s reported over the handshake frames: %s" %
                                (key, text))

def wait_interims_with_traffic(acct, dev, hapd, count, timeout):
    # Interim reports aggregate only fresh samples, so keep data flowing
    # while waiting. Traffic is not a ctrl_iface query and resets nothing.
    # hapd may be a list, for an MLD station.
    return acct.wait_for(ACCT_INTERIM, count=count, timeout=timeout,
                         tick=lambda: drive_traffic_for(dev, hapd, 0))

def test_wifi_stats_radius_interim_and_reset(dev, apdev):
    """wifi_stats report span in RADIUS Accounting interim updates"""
    interim = 5
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_span": "report",
             "wifi_stats_metric_rssi": "AVG-LIN"},
            interim=interim))
        connect_sta(dev[0], hapd)
        # No ctrl_iface queries here; they would confound the measurement.
        interims = wait_interims_with_traffic(acct, dev[0], hapd, 3, 40)

        spans = []
        for pkt in interims[:3]:
            text = connect_info_of(pkt)
            ci = parse(text)
            rssi = ci.get("RSSI")
            if rssi is None or rssi.span is None:
                raise Exception("Interim updates carry no aggregated RSSI")
            secs = span_seconds(rssi.span)
            if secs is None:
                raise Exception("RSSI span is not a duration")
            spans.append(secs)
            # Every metric covers "the last time the connect-info was
            # signaled" to now, so one report's spans agree.
            all_spans = [span_seconds(a.span) for a in ci.attrs
                         if span_seconds(a.span) is not None]
            if max(all_spans) - min(all_spans) > 1:
                raise Exception("Spans within one report disagree: %s" %
                                text)
        logger.info("interim spans: %r" % spans)

        # Each report covers only the interval since the previous one; an
        # accumulator that never resets grows across reports instead.
        if spans[2] > spans[0] + 3:
            raise Exception("Spans %r grow with each report" % spans)
        for secs in spans:
            if secs > interim + 3:
                raise Exception("Span %ds far exceeds the %ds interim "
                                "interval: %r" % (secs, interim, spans))

def test_wifi_stats_report_span_exceeds_window(dev, apdev):
    """wifi_stats report span with the interim interval above the window"""
    # With accounting the period bound follows the interim interval, not the
    # 10 s window.
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_wba_window": "10",
             "wifi_stats_span": "report"}, interim=25))
        connect_sta(dev[0], hapd)
        interims = wait_interims_with_traffic(acct, dev[0], hapd, 2, 70)
        text = connect_info_of(interims[1])
        tx = parse(text).get("TxBitRate")
        if tx is None or span_seconds(tx.span) is None:
            raise Exception("No aggregated TxBitRate: %s" % text)
        if span_seconds(tx.span) < 20:
            raise Exception("A 25 s interim covers only %ds: %s" %
                            (span_seconds(tx.span), text))

def test_wifi_stats_radius_window_span_independent(dev, apdev):
    """wifi_stats window span in RADIUS Accounting interim updates"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_wba_window": "10",
             "wifi_stats_span": "window"}, interim=25))
        connect_sta(dev[0], hapd)
        # Only fresh samples are aggregated; without traffic nothing below
        # is checked.
        interims = wait_interims_with_traffic(acct, dev[0], hapd, 2, 90)
        for pkt in interims[:2]:
            ci = parse(connect_info_of(pkt))
            spans = [(a.key, span_seconds(a.span)) for a in ci.attrs
                     if span_seconds(a.span) is not None]
            if not spans:
                raise Exception("No aggregated metric in an interim update "
                                "sent under traffic: %s" % ci.text)
            for key, secs in spans:
                if secs > 10:
                    raise Exception("%s span %ds exceeds the 10 s sliding "
                                    "window" %
                                    (key, secs))

def test_wifi_stats_default_span(dev, apdev):
    """wifi_stats default span in RADIUS Accounting interim updates"""
    interim = 8
    with AcctCapture() as acct:
        # No span, window or interval directive: the defaults are the subject.
        hapd = start_ap(apdev[0], acct_params(interim=interim))
        status = wifi_stats_status(hapd)
        if status.get("span") != "window" or status.get("window") != "60":
            raise Exception("Default span=%r window=%r, expected window/60" %
                            (status.get("span"), status.get("window")))
        connect_sta(dev[0], hapd)
        parse(connect_info_of(acct.wait_for(ACCT_START)[0]))
        # No ctrl_iface queries here; they would confound the measurement.
        interims = wait_interims_with_traffic(acct, dev[0], hapd, 2, 40)

        spans = []
        for pkt in interims[:2]:
            text = connect_info_of(pkt)
            ci = parse(text)
            rssi = ci.get("RSSI")
            if rssi is None or span_seconds(rssi.span) is None:
                raise Exception("An interim update sent under traffic carries "
                                "no aggregated RSSI: %s" % text)
            spans.append(span_seconds(rssi.span))
            for a in ci.attrs:
                secs = span_seconds(a.span)
                if secs is not None and secs > 60:
                    raise Exception("%s span %ds exceeds the 60 s default "
                                    "window: %s" % (a.key, secs, text))
        logger.info("interim spans: %r" % spans)

        # The station has been associated for less than the window, so the
        # second report covers the samples of the first and the interim
        # interval since, less up to 3 s of collection tick jitter.
        if spans[1] < spans[0] + interim - 3:
            raise Exception("Spans %r: second interim does not extend the "
                            "first by %ds" %
                            (spans, interim))

def test_wifi_stats_radius_accounting_stop(dev, apdev):
    """wifi_stats Connect-Info in RADIUS Accounting-Request (Stop)"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_span": "report"}))
        connect_sta(dev[0], hapd)
        drive_traffic_for(dev[0], hapd, 8)
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()

        stop = acct.wait_for(ACCT_STOP)[0]
        text = connect_info_of(stop)
        if text is None:
            raise Exception("Accounting-Stop carries no Connect-Info")
        logger.info("Accounting-Stop Connect-Info: %s" % text)
        ci = parse(text)
        # A Stop built after the station state is torn down is well formed
        # but full of zeros.
        rssi = ci.get("RSSI")
        if rssi is None:
            raise Exception("Accounting-Stop carries no RSSI: %s" % text)
        if int(rssi.value) == 0:
            raise Exception("Accounting-Stop reports RSSI:0: %s" % text)
        if ci.maxspeed is not None and ci.maxspeed == 0:
            raise Exception("Accounting-Stop reports a zero max rate: %s" %
                            text)

def check_legacy_connect_info(text):
    # The legacy string is deliberately not draft-conformant. This guards the
    # fallback branch's existence, not its conformance.
    if text is None:
        raise Exception("No Connect-Info at all")
    for token in ["RSSI:", "TxBitRate:", "RxBitRate:", "FrameLoss:",
                  "FrameRetry:", "Global-OC:", "Channel:", "("]:
        if token in text:
            raise Exception("WBA token %r present while disabled: %s" %
                            (token, text))
    if not text.startswith("CONNECT "):
        raise Exception("Unexpected legacy format: %s" % text)

def test_wifi_stats_radius_legacy_fallback(dev, apdev):
    """wifi_stats disabled explicitly and legacy RADIUS Connect-Info"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params({"wifi_stats_wba_enabled": "0"}))
        connect_sta(dev[0], hapd)
        start = acct.wait_for(ACCT_START)[0]
        text = connect_info_of(start)
        logger.info("legacy Connect-Info: %s" % text)
        check_legacy_connect_info(text)

def test_wifi_stats_radius_default_is_legacy(dev, apdev):
    """wifi_stats not configured and legacy RADIUS Connect-Info"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(), wba_enabled=None)
        connect_sta(dev[0], hapd)
        start = acct.wait_for(ACCT_START)[0]
        text = connect_info_of(start)
        logger.info("default Connect-Info: %s" % text)
        check_legacy_connect_info(text)

def connect_info_refused(hapd, addr):
    return hapd.request("WIFI_STATS_CONNECT_INFO " + addr).startswith("FAIL")

def aggregated_attrs(ci):
    return [a for a in ci.attrs if a.algo is not None]

def test_wifi_stats_disabled_by_default(dev, apdev):
    """wifi_stats disabled by default and enabled with SET"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"}, wba_enabled=None)
    if wifi_stats_status(hapd).get("wba_enabled") != "0":
        raise Exception("wifi_stats_wba_enabled does not default to 0: %r" %
                        wifi_stats_status(hapd))
    addr = connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 3)
    if not connect_info_refused(hapd, addr):
        raise Exception("Connect-Info returned for a station while disabled")

    hapd.set("wifi_stats_wba_enabled", "1")
    if wifi_stats_status(hapd).get("wba_enabled") != "1":
        raise Exception("SET did not enable: %r" % wifi_stats_status(hapd))
    drive_traffic_for(dev[0], hapd, 5)
    ci = conn_info(hapd, addr)
    if not aggregated_attrs(ci):
        raise Exception("Nothing aggregated 5 s after enabling under "
                        "traffic: %s" %
                        ci.text)

    hapd.set("wifi_stats_wba_enabled", "0")
    if wifi_stats_status(hapd).get("wba_enabled") != "0":
        raise Exception("SET did not disable: %r" % wifi_stats_status(hapd))
    if not connect_info_refused(hapd, addr):
        raise Exception("Connect-Info still returned after disabling")

    # Traffic while disabled: collecting on would show up in the spans below.
    drive_traffic_for(dev[0], hapd, 4)
    enabled_at = time.time()
    hapd.set("wifi_stats_wba_enabled", "1")
    ci = conn_info(hapd, addr)
    elapsed = time.time() - enabled_at
    for a in ci.attrs:
        secs = span_seconds(a.span)
        if secs is not None and secs > elapsed + 1:
            raise Exception("%s spans %ds, %.1fs after enabling: %s" %
                            (a.key, secs, elapsed, ci.text))

    drive_traffic_for(dev[0], hapd, 5)
    ci = conn_info(hapd, addr)
    elapsed = time.time() - enabled_at
    if not aggregated_attrs(ci):
        raise Exception("Nothing aggregated after enabling again: %s" %
                        ci.text)
    for a in ci.attrs:
        secs = span_seconds(a.span)
        if secs is not None and secs > elapsed + 1:
            raise Exception("%s spans %ds, %.1fs after enabling: %s" %
                            (a.key, secs, elapsed, ci.text))

def test_wifi_stats_enabled_across_reload(dev, apdev):
    """wifi_stats enabled state over reload and interface restart"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"})
    addr = connect_sta(dev[0], hapd)

    # RELOAD and RELOAD_CONFIG take different paths in hostapd; with the
    # configuration in memory both deauthenticate and re-apply it.
    for cmd in ["RELOAD", "RELOAD_CONFIG"]:
        if "OK" not in hapd.request(cmd):
            raise Exception("%s failed" % cmd)
        hapd.wait_sta(timeout=10)
        if wifi_stats_status(hapd).get("wba_enabled") != "1":
            raise Exception("%s cleared wifi_stats_wba_enabled" % cmd)
        drive_traffic_for(dev[0], hapd, 5)
        ci = conn_info(hapd, addr)
        if not aggregated_attrs(ci):
            raise Exception("Nothing aggregated after %s: %s" % (cmd, ci.text))

    hapd.set("wifi_stats_wba_enabled", "0")
    for cmd in ["RELOAD", "RELOAD_CONFIG"]:
        if "OK" not in hapd.request(cmd):
            raise Exception("%s failed" % cmd)
        hapd.wait_sta(timeout=10)
        if wifi_stats_status(hapd).get("wba_enabled") != "0":
            raise Exception("%s set wifi_stats_wba_enabled" % cmd)
        if not connect_info_refused(hapd, addr):
            raise Exception("Connect-Info returned after %s while disabled" %
                            cmd)

    def restart():
        # The reloads above left connection events queued on the station.
        dev[0].dump_monitor()
        hapd.disable()
        dev[0].wait_disconnected(timeout=10)
        hapd.dump_monitor()
        hapd.enable()
        ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=30)
        if ev is None or "AP-ENABLED" not in ev:
            raise Exception("AP did not start again")
        hapd.wait_sta(timeout=30)

    restart()
    if wifi_stats_status(hapd).get("wba_enabled") != "0":
        raise Exception("Restart enabled wifi_stats")
    if not connect_info_refused(hapd, addr):
        raise Exception("Connect-Info returned after a restart while disabled")

    # The context of the restarted interface never ran; enable it now.
    hapd.set("wifi_stats_wba_enabled", "1")
    drive_traffic_for(dev[0], hapd, 5)
    ci = conn_info(hapd, addr)
    if not aggregated_attrs(ci):
        raise Exception("Nothing aggregated after enabling a restarted "
                        "interface: %s" % ci.text)

    restart()
    if wifi_stats_status(hapd).get("wba_enabled") != "1":
        raise Exception("Restart disabled wifi_stats")
    drive_traffic_for(dev[0], hapd, 5)
    ci = conn_info(hapd, addr)
    if not aggregated_attrs(ci):
        raise Exception("Nothing aggregated after a restart while enabled: "
                        "%s" % ci.text)

def test_wifi_stats_failed_set_keeps_state(dev, apdev):
    """wifi_stats state after a failed SET"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"})
    addr = connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 4)
    if not aggregated_attrs(conn_info(hapd, addr)):
        raise Exception("Nothing aggregated under traffic")

    # SET stores a value before it checks the configuration as a whole. A
    # contention window maximum below the minimum fails that check, and so
    # does every later SET, each still storing its value.
    try:
        if not set_rejected(hapd, "tx_queue_data2_cwmax", "3"):
            raise Exception("TX cwMax < cwMin accepted")
        if not set_rejected(hapd, "wifi_stats_wba_enabled", "0"):
            raise Exception("SET accepted with an invalid configuration")
        # Nothing was stopped, so nothing may be reported as stopped.
        if wifi_stats_status(hapd).get("wba_enabled") != "1":
            raise Exception("A failed SET changed the reported state: %r" %
                            wifi_stats_status(hapd))
        drive_traffic_for(dev[0], hapd, 4)
        ci = conn_info(hapd, addr)
        if not aggregated_attrs(ci):
            raise Exception("Nothing aggregated after a failed SET: %s" %
                            ci.text)
    finally:
        hapd.request("SET tx_queue_data2_cwmax 63")

    hapd.set("wifi_stats_wba_enabled", "1")
    if wifi_stats_status(hapd).get("wba_enabled") != "1":
        raise Exception("Not enabled after a successful SET")
    ci = conn_info(hapd, addr)
    if not aggregated_attrs(ci):
        raise Exception("The statistics were dropped although collection "
                        "never stopped: %s" % ci.text)

def test_wifi_stats_degenerate_spans(dev, apdev):
    """wifi_stats Connect-Info with no samples and degenerate spans"""
    cases = [
        ("no samples yet", {"wifi_stats_interval": "1"}, 0),
        ("no samples yet, report span", {"wifi_stats_interval": "1",
                                         "wifi_stats_span": "report"}, 0),
        ("window equals interval", {"wifi_stats_interval": "1",
                                    "wifi_stats_wba_window": "1",
                                    "wifi_stats_span": "window"}, 3),
        ("interval exceeds window", {"wifi_stats_interval": "10",
                                     "wifi_stats_wba_window": "2",
                                     "wifi_stats_span": "window"}, 3),
    ]
    for name, extra, settle in cases:
        hapd = start_ap(apdev[0], extra)
        try:
            addr = connect_sta(dev[0], hapd)
            if settle:
                time.sleep(settle)
            text = conn_info_raw(hapd, addr)
            logger.info("%s: %s" % (name, text))
            parse(text)
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def test_wifi_stats_sta_rejoin(dev, apdev):
    """wifi_stats span after reassociation"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"})
    addr = connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 6)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    time.sleep(2)

    connect_sta(dev[0], hapd)
    drive_traffic_for(dev[0], hapd, 2)
    text = conn_info_raw(hapd, addr)
    ci = parse(text)

    # Two seconds of traffic since the reassociation give a span of about a
    # second. Statistics kept from the first association would show the
    # seven to ten seconds since its samples.
    for a in ci.attrs:
        secs = span_seconds(a.span)
        if secs is not None and secs > 4:
            raise Exception("%s span %ds carries over from the previous "
                            "association: %s" % (a.key, secs, text))

def test_wifi_stats_runtime_reconfigure(dev, apdev):
    """wifi_stats reconfiguration with SET while a station is associated"""
    hapd = start_ap(apdev[0])
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)

    # Configuration key, value, and the WIFI_STATS_STATUS key showing it
    sequence = [
        ("wifi_stats_interval", "3600", "interval"),
        ("wifi_stats_interval", "1", "interval"),
        ("wifi_stats_wba_window", "3600", "window"),
        ("wifi_stats_wba_window", "1", "window"),
        ("wifi_stats_wba_window", "60", "window"),
        ("wifi_stats_span", "report", "span"),
        ("wifi_stats_span", "window", "span"),
        ("wifi_stats_ewma_weight", "9", "ewma_weight"),
        ("wifi_stats_ewma_weight", "1", "ewma_weight"),
        ("wifi_stats_metric_rssi", "AVG-EXP", "RSSI"),
        ("wifi_stats_metric_rssi", "MIN", "RSSI"),
        ("wifi_stats_metric_txbitrate", "MIN", "TxBitRate"),
        ("wifi_stats_metric_txbitrate", "MAX", "TxBitRate"),
        ("wifi_stats_metric_rxbitrate", "AVG-LIN", "RxBitRate"),
        ("wifi_stats_metric_frameloss", "NONE", "FrameLoss"),
        ("wifi_stats_metric_frameretry", "NONE", "FrameRetry"),
        ("wifi_stats_metric_frameloss", "ACC", "FrameLoss"),
    ]
    for key, value, shown in sequence:
        before = wifi_stats_status(hapd)
        hapd.set(key, value)
        status = wifi_stats_status(hapd)
        if status.get(shown) != value:
            raise Exception("SET %s %s shows %s=%r" %
                            (key, value, shown, status.get(shown)))
        # One directive changes one setting.
        for other in status:
            if other != shown and status[other] != before.get(other):
                raise Exception("SET %s %s changed %s from %r to %r" %
                                (key, value, other, before.get(other),
                                 status[other]))
        parse(conn_info_raw(hapd, addr))

    # The formatter uses what STATUS shows.
    hapd.set("wifi_stats_interval", "1")
    hapd.set("wifi_stats_metric_rssi", "MIN")
    drive_traffic_for(dev[0], hapd, 5)
    ci = conn_info(hapd, addr)
    rssi = ci.get("RSSI")
    if rssi is None or rssi.algo != "MIN":
        raise Exception("RSSI set to MIN at runtime is not reported as MIN: "
                        "%s" % ci.text)

    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd stopped responding")

def test_wifi_stats_config_reload(dev, apdev):
    """wifi_stats runtime settings over RELOAD and RELOAD_CONFIG"""
    # SET applies a wifi_stats directive at once, so a reload has nothing new
    # to apply and must keep the settings. Reloading a changed configuration
    # file is not covered here.
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "60",
                               "wifi_stats_span": "window",
                               "wifi_stats_metric_rssi": "MAX"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(3)

    hapd.set("wifi_stats_wba_window", "5")
    hapd.set("wifi_stats_metric_rssi", "MIN")
    hapd.set("wifi_stats_ewma_weight", "3")
    for cmd in ["RELOAD", "RELOAD_CONFIG"]:
        if "OK" not in hapd.request(cmd):
            raise Exception("%s failed" % cmd)
        hapd.wait_sta(timeout=10)
        # The reload deauthenticated the station, so its statistics start
        # over. Longer than the window: one that was not applied would show.
        drive_traffic_for(dev[0], hapd, 8)

        status = wifi_stats_status(hapd)
        if status.get("window") != "5" or status.get("RSSI") != "MIN" or \
           status.get("ewma_weight") != "3" or status.get("span") != "window":
            raise Exception("%s lost the settings: %r" % (cmd, status))

        # Reporting the configuration is not enough; the formatter must use
        # it.
        ci = conn_info(hapd, addr)
        rssi = ci.get("RSSI")
        if rssi is None or rssi.algo != "MIN":
            raise Exception("Status reports MIN after %s but the attribute "
                            "does not: %s" % (cmd, ci.text))
        secs = span_seconds(rssi.span)
        if secs is None or secs > 5:
            raise Exception("Span %r exceeds the 5 s window after %s: %s" %
                            (rssi.span, cmd, ci.text))

def test_wifi_stats_config_invalid(dev, apdev):
    """wifi_stats invalid configuration values"""
    # Positive control: a systemic harness failure would otherwise make
    # every row below vacuously pass at once.
    good_params = hostapd.wpa2_params(ssid="wifi-stats-good",
                                      passphrase=PASSPHRASE)
    good_params["wifi_stats_wba_window"] = "60"
    add_ap(apdev[0], good_params)
    hostapd.remove_bss(apdev[0])

    out_of_range = [
        ("wifi_stats_interval", "0"),
        ("wifi_stats_interval", "3601"),
        ("wifi_stats_interval", "abc"),
        # Negative, and equal to a valid value modulo 2^64.
        ("wifi_stats_interval", "-18446744073709551615"),
        ("wifi_stats_wba_window", "0"),
        ("wifi_stats_wba_window", "3601"),
        ("wifi_stats_wba_window", "-18446744073709551615"),
        ("wifi_stats_wba_enabled", "2"),
        ("wifi_stats_span", "sliding"),
        ("wifi_stats_ewma_weight", "0"),
        ("wifi_stats_ewma_weight", "10"),
        ("wifi_stats_ewma_weight", "-18446744073709551615"),
        ("wifi_stats_metric_bogus", "MAX"),
        ("wifi_stats_metric_rssi", "BOGUS"),
        # ALGO has no bare-AVG alternative.
        ("wifi_stats_metric_rssi", "AVG"),
    ]

    # Grammatical, but rejected by hostapd policy.
    local_policy = [
        ("wifi_stats_metric_frameloss", "MIN"),
        ("wifi_stats_metric_rssi", "ACC"),
    ]

    bad = [(k, v, "which is out of range") for k, v in out_of_range] + \
          [(k, v, "which hostapd rejects as a local policy stricter than "
            "the draft") for k, v in local_policy]
    for key, value, why in bad:
        params = hostapd.wpa2_params(ssid="wifi-stats-bad",
                                     passphrase=PASSPHRASE)
        params[key] = value
        started = False
        try:
            hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
            started = "OK" in hapd.request("ENABLE")
        except Exception as e:
            if "Failed to set hostapd parameter " + key not in str(e):
                raise Exception("%s=%s failed for an unrelated reason: %s" %
                                (key, value, e))
            started = False
        finally:
            try:
                hostapd.remove_bss(apdev[0])
            except Exception:
                pass
        if started:
            raise Exception("AP started with %s=%s, %s" % (key, value, why))

def test_wifi_stats_ctrl_validation(dev, apdev):
    """wifi_stats invalid values in SET"""
    # Non-default values, so that a rejected SET falling back to a default
    # shows as a change.
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "2",
                               "wifi_stats_wba_window": "30",
                               "wifi_stats_span": "report",
                               "wifi_stats_ewma_weight": "4",
                               "wifi_stats_metric_rssi": "MAX",
                               "wifi_stats_metric_txbitrate": "MIN"})
    ratio_only = ["MIN", "MAX", "AVG-LIN", "AVG-EXP"]
    checks = [
        ("wifi_stats_interval", ["0", "3601", "abc", "", "5x", "-1", "1.5",
                               "-18446744073709551615"]),
        ("wifi_stats_wba_window", ["0", "3601", "abc", "", "5x", "-1",
                                 "-18446744073709551615"]),
        ("wifi_stats_ewma_weight", ["0", "10", "abc", "", "5x", "-1",
                                  "-18446744073709551615"]),
        ("wifi_stats_span", ["sliding", "", "report x"]),
        ("wifi_stats_wba_enabled", ["2", "-1", "abc", "", "1x"]),
        ("wifi_stats_metric_rssi", ["BOGUS", "AVG", "ACC", ""]),
        ("wifi_stats_metric_txbitrate", ["ACC", "AVG"]),
        ("wifi_stats_metric_rxbitrate", ["ACC", "AVG"]),
        ("wifi_stats_metric_frameloss", ratio_only + ["AVG"]),
        ("wifi_stats_metric_frameretry", ratio_only + ["AVG"]),
        ("wifi_stats_metric_bogus", ["MAX", "NONE"]),
        ("wifi_stats_metric_", ["MAX"]),
        ("wifi_stats_bogus", ["1"]),
    ]
    before = wifi_stats_status(hapd)
    if before.get("interval") != "2" or before.get("RSSI") != "MAX" or \
       before.get("span") != "report":
        raise Exception("Unexpected starting point: %r" % before)
    for key, values in checks:
        for value in values:
            if not set_rejected(hapd, key, value):
                raise Exception("SET %s %r was accepted" % (key, value))
            after = wifi_stats_status(hapd)
            if after != before:
                raise Exception("Rejected SET %s %r changed %r to %r" %
                                (key, value, before, after))

    # A rejected value must not linger in the configuration either: an
    # accepted SET applies every wifi_stats directive again and would bring
    # it out.
    hapd.set("wifi_stats_ewma_weight", "4")
    after = wifi_stats_status(hapd)
    if after != before:
        raise Exception("A rejected value was kept and applied later: %r "
                        "to %r" % (before, after))
    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd stopped responding")

def test_wifi_stats_set_keeps_period(dev, apdev):
    """wifi_stats aggregation period kept over SET"""
    for span in ["report", "window"]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "60",
                                   "wifi_stats_span": span,
                                   "wifi_stats_metric_rssi": "AVG-LIN"})
        try:
            addr = connect_sta(dev[0], hapd)
            drive_traffic_for(dev[0], hapd, 8)
            first = conn_info(hapd, addr).get("RSSI")
            if first is None or span_seconds(first.span) is None:
                raise Exception("%s: no aggregated RSSI after 8 s" % span)

            # One changed value, then values already in effect; every SET
            # applies all the directives again.
            hapd.set("wifi_stats_ewma_weight", "3")
            hapd.set("wifi_stats_interval", "1")
            hapd.set("wifi_stats_wba_window", "60")
            hapd.set("wifi_stats_span", span)
            hapd.set("wifi_stats_metric_rssi", "AVG-LIN")
            hapd.set("wifi_stats_wba_enabled", "1")

            second = conn_info(hapd, addr).get("RSSI")
            if second is None or span_seconds(second.span) is None:
                raise Exception("%s: no aggregate after SET" % span)
            if span_seconds(second.span) + 1 < span_seconds(first.span):
                raise Exception("%s: the span fell from %ds to %ds across "
                                "SET" % (span, span_seconds(first.span),
                                         span_seconds(second.span)))
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def test_wifi_stats_timing_change_restarts(dev, apdev):
    """wifi_stats period restart on span, interval or window change"""
    # Per change: key, value, seconds of traffic after it and the longest span
    # that the samples taken since the change can give. Samples kept from
    # before the change would give a longer one.
    for key, value, seconds, bound in [("wifi_stats_wba_window", "30", 4, 5),
                                       ("wifi_stats_span", "report", 4, 5),
                                       ("wifi_stats_interval", "2", 8, 6)]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "60",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_metric_rssi": "AVG-LIN"})
        try:
            addr = connect_sta(dev[0], hapd)
            drive_traffic_for(dev[0], hapd, 8)
            before = conn_info(hapd, addr).get("RSSI")
            if before is None or span_seconds(before.span) is None:
                raise Exception("%s: no aggregated RSSI after 8 s" % key)

            hapd.set(key, value)

            # With the buffers gone the next query has at most one sample:
            # an instantaneous value without a span.
            now = conn_info(hapd, addr).get("RSSI")
            if now is None:
                raise Exception("%s: no RSSI right after the change" % key)
            if now.span is not None:
                raise Exception("%s: RSSI still aggregated (%s) right after "
                                "the change" % (key, now.span))

            drive_traffic_for(dev[0], hapd, seconds)
            after = conn_info(hapd, addr).get("RSSI")
            if after is None or span_seconds(after.span) is None:
                raise Exception("%s: no aggregated RSSI %ds after the change" %
                                (key, seconds))
            if span_seconds(after.span) > bound:
                raise Exception("%s: the span is %ds, samples from before "
                                "the change were kept" %
                                (key, span_seconds(after.span)))
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()

def run_wifi_stats_multiple_sta(dev, hapd, addrs):
    # Without distinct values, an implementation sharing one set of
    # statistics across stations would look correct.
    levels = [-45, -40, -35]
    distinct = True
    try:
        for d, level in zip(dev[0:3], levels):
            set_sta_rssi(d, hapd, level)
    except HwsimSkip:
        distinct = False
    end = time.time() + 3
    while time.time() < end:
        for d in dev[0:3]:
            drive_traffic(d, hapd, count=1)

    reported = {}
    for addr in addrs:
        ci = conn_info(hapd, addr)
        sta = hapd.get_sta(addr)
        rssi = ci.get("RSSI")
        if rssi is None:
            continue
        reported[addr] = int(rssi.value)
        if 'signal' in sta:
            if abs(abs(int(rssi.value)) - abs(int(sta['signal']))) > 12:
                raise Exception("%s reports RSSI %s but the driver says %s" %
                                (addr, rssi.value, sta['signal']))

    blocks = set()
    for addr in addrs:
        ci = conn_info(hapd, addr)
        blocks.add((ci.maxspeed, ci.amendment))
    if len(blocks) != 1:
        raise Exception("Stations of one BSS report different legacy "
                        "blocks: %r" % blocks)

    if distinct and len(reported) == 3:
        if len(set(reported.values())) == 1:
            raise Exception("All three stations report the same RSSI %r "
                            "despite being driven to %r" %
                            (reported, levels))

    # Repeatedly reading one station must not disturb another's span.
    before = conn_info(hapd, addrs[1]).get("RSSI")
    for i in range(5):
        conn_info(hapd, addrs[0])
    after = conn_info(hapd, addrs[1]).get("RSSI")
    if before is not None and after is not None and before.span and after.span:
        b, a = span_seconds(before.span), span_seconds(after.span)
        if b is not None and a is not None and a + 2 < b:
            raise Exception("Reading one station shortened another's span "
                            "from %ds to %ds" % (b, a))

def test_wifi_stats_multiple_sta(dev, apdev):
    """wifi_stats Connect-Info with multiple stations"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "10",
                               "wifi_stats_span": "window"})
    addrs = []
    for d in dev[0:3]:
        addrs.append(connect_sta(d, hapd))
    try:
        run_wifi_stats_multiple_sta(dev, hapd, addrs)
    finally:
        # set_sta_rssi() leaves a fixed TX power on the station radios.
        for d in dev[0:3]:
            try:
                hwsim_utils.reset_rx_rssi(d)
            except Exception:
                pass

def test_wifi_stats_vlan_sta(dev, apdev):
    """wifi_stats with a station on an AP_VLAN interface"""
    # A station on an AP_VLAN interface is not in the station dump of the AP
    # interface and is read separately. The accept file puts dev[0] on VLAN 1;
    # dev[2] stays on the AP interface.
    filename = hostapd.acl_file(dev, apdev, 'hostapd.accept')
    hostapd.send_file(apdev[0], filename, filename)
    try:
        params = {"ssid": "wifi-stats-vlan",
                  "dynamic_vlan": "1",
                  "accept_mac_file": filename,
                  "wifi_stats_wba_enabled": "1",
                  "wifi_stats_interval": "1"}
        hapd = add_ap(apdev[0], params)
        check_wifi_stats(hapd)

        stas = [(dev[0], "brvlan1"), (dev[2], None)]
        for d, bridge in stas:
            d.connect("wifi-stats-vlan", key_mgmt="NONE", scan_freq="2412")
            hapd.wait_sta()

        # RSSI is aggregated only over samples with received frames in
        # between, so keep both stations busy across several intervals.
        end = time.time() + 4
        while True:
            hwsim_utils.test_connectivity_iface(dev[0], hapd, "brvlan1")
            hwsim_utils.test_connectivity(dev[2], hapd)
            if time.time() >= end:
                break
            time.sleep(0.3)

        for d, bridge in stas:
            addr = d.own_addr()
            where = "on %s" % bridge if bridge else "without a VLAN"
            ci = conn_info(hapd, addr)
            rssi = ci.get("RSSI")
            if rssi is None or rssi.algo != "AVG-LIN":
                raise Exception("No aggregated RSSI for the station %s: %s" %
                                (where, ci.text))
            sta = hapd.get_sta(addr)
            if 'signal' not in sta:
                raise Exception("No driver signal for the station %s" % where)
            if abs(abs(int(rssi.value)) - abs(int(sta['signal']))) > 10:
                raise Exception("Station %s: RSSI %s differs from the "
                                "driver's %s by more than 10 dB" %
                                (where, rssi.value, sta['signal']))
    finally:
        if filename.startswith('/tmp/'):
            os.unlink(filename)

def test_wifi_stats_oom(dev, apdev):
    """wifi_stats OOM"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"})
    with alloc_fail(hapd, 1, "wifi_stats_sta_buf_alloc"):
        connect_sta(dev[0], hapd)
        wait_fail_trigger(hapd, "GET_ALLOC_FAIL",
                          note="wifi_stats_sta_buf_alloc failure not triggered")
        res = hapd.request("WIFI_STATS_CONNECT_INFO " + dev[0].own_addr())
        if not res.startswith("FAIL") and not is_valid(res.strip()):
            raise Exception("A half-built attribute was returned under OOM: "
                            "%r" % res)
    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd died on an allocation failure")

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)
    parse(conn_info_raw(hapd, addr))

def test_wifi_stats_bad_station_arguments(dev, apdev):
    """wifi_stats WIFI_STATS_CONNECT_INFO with invalid station arguments"""
    hapd = start_ap(apdev[0])
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)

    bad = ["", "zz:zz:zz:zz:zz:zz", "00:11:22", "z" * 200,
           "02:00:00:00:ff:ff", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
           apdev[0]['bssid'], "02:00:00 :00:00:01"]
    for arg in bad:
        cmd = ("WIFI_STATS_CONNECT_INFO " + arg).strip()
        res = hapd.request(cmd)
        if not rejected(res):
            raise Exception("%r returned %r instead of a rejection" %
                            (cmd, res))
        if "PONG" not in hapd.request("PING"):
            raise Exception("hostapd stopped responding after %r" % cmd)

    parse(conn_info_raw(hapd, addr))

def test_wifi_stats_rates_instantaneous_before_traffic(dev, apdev):
    """wifi_stats instantaneous bit rates before data traffic"""
    # Before data the rate is the handshake's: instantaneous, never a
    # maximum. A 10 s interval leaves fewer than two samples at first query.
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "10"})
    addr = connect_sta(dev[0], hapd)
    ci = conn_info(hapd, addr)
    for key in ["TxBitRate", "RxBitRate"]:
        a = ci.get(key)
        if a is not None and a.algo is not None:
            raise Exception("%s carries %s before any data: %s" %
                            (key, a.algo, ci.text))

    hapd.set("wifi_stats_interval", "1")
    drive_traffic_for(dev[0], hapd, 4)
    ci = conn_info(hapd, addr)
    tx = ci.get("TxBitRate")
    if tx is None or tx.algo != "MAX":
        raise Exception("No aggregated TxBitRate after data: %s" % ci.text)

def test_wifi_stats_acc_min_frames(dev, apdev):
    """wifi_stats FrameLoss and FrameRetry minimum frame count"""
    # One retry among four handshake frames would read 25%; sustained traffic
    # passes the 20-frame floor.
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"})
    addr = connect_sta(dev[0], hapd)
    ci = conn_info(hapd, addr)
    for key in ["FrameLoss", "FrameRetry"]:
        if ci.get(key) is not None:
            raise Exception("%s reported right after association: %s" %
                            (key, ci.text))
    drive_traffic_for(dev[0], hapd, 5, pause=0)
    ci = conn_info(hapd, addr)
    for key in ["FrameLoss", "FrameRetry"]:
        a = ci.get(key)
        if a is None or a.algo != "ACC":
            raise Exception("%s missing after sustained traffic: %s" %
                            (key, ci.text))

MLD_SSID = "wifi-stats-mld"
MLD_CHANNELS = {0: 1, 1: 6}

def mld_params(link, extra=None):
    params = eht_mld_ap_wpa2_params(MLD_SSID, PASSPHRASE, key_mgmt="SAE",
                                    mfp="2", pwe="1")
    params["wifi_stats_wba_enabled"] = "1"
    params["wifi_stats_interval"] = "1"
    params["channel"] = str(MLD_CHANNELS[link])
    if extra:
        params.update(extra)
    return params

def mld_link_ap(hapd_iface, link, params):
    # eht_mld_enable_ap() with the probe between adding the link and setting
    # the wifi_stats_* parameters, as add_ap() does
    plain, stats = split_wifi_stats(params)
    hapd = hostapd.add_mld_link(hapd_iface, link, plain)
    probe_wifi_stats(hapd)
    set_wifi_stats(hapd, stats)
    hapd.enable()
    ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=1)
    if ev is None:
        raise Exception("AP startup timed out")
    if "AP-ENABLED" not in ev:
        raise Exception("AP startup failed")
    return hapd

def mld_ap(hapd_iface, links, extra=None):
    hapds = []
    for link in range(links):
        hapds.append(mld_link_ap(hapd_iface, link,
                                 mld_params(link, extra)))
    check_wifi_stats(hapds[0])
    return hapds

def mld_wpas(wpas_iface):
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add(wpas_iface)
    check_sae_capab(wpas)
    return wpas

def mld_connect(wpas, hapds):
    wpas.set("sae_pwe", "1")
    freqs = " ".join(str(2407 + 5 * MLD_CHANNELS[i]) for i in range(len(hapds)))
    wpas.connect(MLD_SSID, sae_password=PASSPHRASE, scan_freq=freqs,
                 key_mgmt="SAE", ieee80211w="2", beacon_prot="1")
    for h in hapds:
        h.wait_sta()
    # The MLD address, which is what hostapd keys the station on
    addr = hapds[0].request("STA-FIRST").splitlines()[0]
    for h in hapds:
        hwsim_utils.test_connectivity(wpas, h)
    return addr

def test_wifi_stats_mlo_global_oc(dev, apdev):
    """wifi_stats Connect-Info Global-OC and MAXSPEED with MLO"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = mld_wpas(wpas_iface)

        # One link first, for the reference maximum of a single link
        hapds = mld_ap(hapd_iface, 1)
        addr = mld_connect(wpas, hapds)
        one = conn_info(hapds[0], addr)
        wpas.request("DISCONNECT")
        wpas.wait_disconnected()
        wpas.request("REMOVE_NETWORK all")
        wpas.request("BSS_FLUSH 0")

        # Then the same AP MLD with a second, identical link
        hapds.append(mld_link_ap(hapd_iface, 1, mld_params(1)))
        addr = mld_connect(wpas, hapds)
        drive_traffic_for(wpas, hapds, 3)
        ci = conn_info(hapds[0], addr)
        logger.info("MLO Connect-Info: %s" % ci.text)

        if ci.amendment != "be":
            raise Exception("An AP MLD reported 802.11%s" % ci.amendment)
        gocs = ci.all("Global-OC")
        if sorted(a.link_id for a in gocs if a.link_id is not None) != [0, 1]:
            raise Exception("Expected Global-OC for links 0 and 1: %s" %
                            ci.text)
        for a in gocs:
            if int(a.value) != 81:
                raise Exception("2.4 GHz 20 MHz link reported class %s" %
                                a.value)
        # Channel: is the association link's, whose Global-OC comes first
        if ci.channel != MLD_CHANNELS[gocs[0].link_id]:
            raise Exception("Channel:%s is not the first Global-OC's link: "
                            "%s" %
                            (ci.channel, ci.text))
        # MAXSPEED is network-level: two identical links, twice one link
        if abs(ci.maxspeed - 2 * one.maxspeed) > 0.011:
            raise Exception("AP MLD MAXSPEED %.2f is not twice the one-link "
                            "%.2f" % (ci.maxspeed, one.maxspeed))
        wpas.request("DISCONNECT")
        wpas.wait_disconnected()

def test_wifi_stats_mlo_same_from_any_link(dev, apdev):
    """wifi_stats Connect-Info from each link of an AP MLD"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        hapds = mld_ap(hapd_iface, 2)
        wpas = mld_wpas(wpas_iface)
        addr = mld_connect(wpas, hapds)
        drive_traffic_for(wpas, hapds, 3)
        # A collection tick between the two reads can move a span; retry.
        for i in range(3):
            a = conn_info_raw(hapds[0], addr)
            b = conn_info_raw(hapds[1], addr)
            if a == b:
                break
            time.sleep(0.2)
        else:
            raise Exception("Links disagree: %s / %s" % (a, b))
        parse(a)
        wpas.request("DISCONNECT")
        wpas.wait_disconnected()

def test_wifi_stats_mlo_accounting(dev, apdev):
    """wifi_stats RADIUS Accounting with MLO"""
    interim = 5
    with AcctCapture() as acct, \
        HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        hapds = mld_ap(hapd_iface, 2, acct_params(
            {"wifi_stats_span": "report"}, interim=interim))
        wpas = mld_wpas(wpas_iface)
        addr = mld_connect(wpas, hapds)
        wait_interims_with_traffic(acct, wpas, hapds, 4, 40)

        starts = acct.of_type(ACCT_START)
        sessions = set(str(p["Acct-Session-Id"][0]) for p in starts)
        # Logged only; the draft does not define sessions per MLD station.
        logger.info("Accounting-Start count %d, sessions %r" %
                    (len(starts), sessions))
        interims = acct.of_type(ACCT_INTERIM)
        if len(interims) < 2:
            raise Exception("Only %d interim updates" % len(interims))
        # A tick between the association link's interim and a partner's can
        # leave the partner one un-aggregated, so only the association link's
        # are held to it; at least one partner interim must be aggregated.
        assoc_session = str(starts[0]["Acct-Session-Id"][0])
        partner_aggregated = 0
        partner_seen = 0
        for pkt in interims[1:]:
            text = connect_info_of(pkt)
            ci = parse(text)
            if ci.count("Global-OC") != 2:
                raise Exception("Interim lacks per-link Global-OC: %s" % text)
            from_assoc = str(pkt["Acct-Session-Id"][0]) == assoc_session
            # Traffic flowed on both links, so an aggregated metric must cover
            # the whole interval. Kernels without per-link or MLD bit rates
            # report no TxBitRate, so fall back to RSSI.
            metric = ci.get("TxBitRate")
            if metric is None or metric.span is None:
                metric = ci.get("RSSI")
            secs = None
            if metric is not None and metric.span is not None:
                secs = span_seconds(metric.span)
            if not from_assoc:
                partner_seen += 1
                if secs is not None and secs >= interim - 2:
                    partner_aggregated += 1
                continue
            if secs is None:
                raise Exception("Neither TxBitRate nor RSSI aggregated in an "
                                "interim update sent under traffic: %s" %
                                text)
            if secs < interim - 2:
                raise Exception("%ds span in a %ds interim: %s" %
                                (secs, interim, text))
        if partner_seen and not partner_aggregated:
            raise Exception("No partner link interim is aggregated")
        wpas.request("DISCONNECT")
        wpas.wait_disconnected()
        # Both links send an Accounting-Stop from hostapd_ml_handle_disconnect
        # and report the same period; compare them when both were captured.
        end = time.time() + 5
        while time.time() < end and len(acct.of_type(ACCT_STOP)) < 2:
            time.sleep(0.3)
        stops = acct.of_type(ACCT_STOP)
        if len(stops) >= 2:
            texts = [connect_info_of(pkt) for pkt in stops[:2]]
            if texts[0] != texts[1]:
                raise Exception("The links' Accounting-Stops differ: %r" %
                                texts)
        else:
            logger.info("only %d Accounting-Stop captured, not comparing" %
                        len(stops))
