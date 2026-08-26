# WBA Connect-Info (wifi_stats) tests
# Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.
#
# Without wmediumd, hwsim never reports TX retries, so FrameLoss and
# FrameRetry are asserted for shape only. RSSI is deterministic through
# set_rx_rssi() and is used to check the aggregation algorithms by value.

import logging
import select
import threading
import time

logger = logging.getLogger()

import hostapd
import hwsim_utils
from utils import *
from connectinfo_abnf import parse, is_valid, ConnectInfoError

SSID = "wifi-stats"
PASSPHRASE = "12345678"

ALL_METRICS = ["RxBitRate", "TxBitRate", "RSSI", "FrameLoss", "FrameRetry"]


def check_wifi_stats(hapd):
    res = hapd.request("WIFI_STATS_STATUS")
    if "UNKNOWN COMMAND" in res or res.startswith("FAIL"):
        raise HwsimSkip("wifi_stats not supported in the build")
    return res


def start_ap(apdev, extra=None, ssid=SSID, **kwargs):
    # No country_code here: run-tests.py fails any test that leaves it set.
    # Only the 5 GHz cases set it, and they pair it with clear_regdom().
    params = hostapd.wpa2_params(ssid=ssid, passphrase=PASSPHRASE)
    if extra:
        params.update(extra)
    hapd = hostapd.add_ap(apdev, params, **kwargs)
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
    res = check_wifi_stats(hapd)
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
    for _i in range(count):
        hwsim_utils.test_connectivity(dev, hapd)


def set_sta_rssi(dev, hapd, value):
    # Make the AP perceive value dBm for this station. Range is -50..-30.
    try:
        hwsim_utils.set_rx_rssi(dev, value)
    except Exception:
        raise HwsimSkip("set_rx_rssi not supported")
    drive_traffic(dev, hapd)


def test_wifi_stats_grammar_strict(dev, apdev):
    """Connect-Info conforms to the draft-10 ABNF across PHY configurations"""
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
        hapd = start_ap(apdev[0], extra)
        try:
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
            else:
                dev[0].request("DISCONNECT")
                dev[0].wait_disconnected()
                hapd.disable()
            dev[0].dump_monitor()


def test_wifi_stats_legacy_attribute_block(dev, apdev):
    """MAXSPEED and WIFIAMENDMENT are emitted atomically and well formed"""
    hapd = start_ap(apdev[0])
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)
    text = conn_info_raw(hapd, addr)
    ci = parse(text)

    # legacyAttributes is a single production: neither half may appear alone.
    if (ci.maxspeed is None) != (ci.amendment is None):
        raise Exception("MAXSPEED and WIFIAMENDMENT are not atomic: %s" % text)
    if ci.maxspeed is None:
        raise Exception("no rate reported at all: %s" % text)

    # The parse enforces the two fractional digits; assert the text too so a
    # regression fails with a readable message rather than a parse error.
    head = text.split(" Mbps")[0]
    frac = head.rsplit(".", 1)[1]
    if len(frac) != 2:
        raise Exception("MAXSPEED must carry exactly two fractional digits, "
                        "got %r in %r" % (frac, text))
    if ci.maxspeed <= 0 or ci.maxspeed >= 100000:
        raise Exception("implausible MAXSPEED %r" % ci.maxspeed)
    if ci.amendment not in ["b", "g", "a", "n", "ac", "ax", "be"]:
        raise Exception("bad amendment %r" % ci.amendment)


def test_wifi_stats_channel_and_op_class(dev, apdev):
    """Channel and Global-OC track the AP configuration"""
    # Global operating classes per Annex E: 2.4 GHz ch1 20 MHz is 81,
    # HT40+ on the same channel is 83, 5 GHz ch36 VHT80 is 128. The draft
    # does not say which channel of a wide BSS is reported, so accept either
    # the primary or the centre - the fourth element of each case.
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
        hapd = start_ap(apdev[0], extra)
        try:
            addr = connect_sta(dev[0], hapd, freq=freq)
            time.sleep(2)
            ci = conn_info(hapd, addr)

            if ci.channel is None:
                raise Exception("%s: no Channel reported" % name)
            if ci.channel not in expect_chan:
                raise Exception("%s: Channel %d is neither the primary nor "
                                "the centre channel of the BSS %r" %
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
        finally:
            if regdom:
                clear_regdom(hapd, dev)
            else:
                dev[0].request("DISCONNECT")
                dev[0].wait_disconnected()
                hapd.disable()
            dev[0].dump_monitor()


def test_wifi_stats_rate_unit(dev, apdev):
    """Bit rates are reported in Mbps, not in a driver counter unit"""
    hapd = start_ap(apdev[0], {"hw_mode": "g", "channel": "1",
                               "ieee80211n": "1"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)
    drive_traffic(dev[0], hapd)
    ci = conn_info(hapd, addr)

    for key in ["RxBitRate", "TxBitRate"]:
        a = ci.get(key)
        if a is None:
            raise Exception("no %s reported" % key)
        value = float(a.value)
        if not 0.0 < value <= 72.2:
            raise Exception("%s %r Mbps is outside the HT20 1SS range - "
                            "unit scaling error?" % (key, value))
        # RATE permits at most one fractional digit.
        if '.' in a.value and len(a.value.split('.')[1]) != 1:
            raise Exception("RATE must carry at most one fractional digit: "
                            "%r" % a.value)


def test_wifi_stats_rssi_form(dev, apdev):
    """RSSI is well formed, consistent in sign and close to the driver value"""
    hapd = start_ap(apdev[0])
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)
    drive_traffic(dev[0], hapd)

    signs = set()
    for _i in range(5):
        ci = conn_info(hapd, addr)
        rssi = ci.get("RSSI")
        if rssi is None:
            raise Exception("no RSSI reported")
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
    """FrameLoss and FrameRetry are present and are integers in 0..100"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "5",
                               "wifi_stats_span": "window"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(6)
    drive_traffic(dev[0], hapd, count=10)
    ci = conn_info(hapd, addr)

    # No non-zero assertion; see the note at the top of this file. Both are
    # expected here: ACC is the default and there has been time to aggregate.
    for key in ["FrameLoss", "FrameRetry"]:
        a = ci.get(key)
        if a is None:
            raise Exception("%s missing with the ACC default and 6s of "
                            "dwell" % key)
        if not a.value.isdigit() or not 0 <= int(a.value) <= 100:
            raise Exception("%s %r is outside PCT (0-100)" % (key, a.value))
        if len(a.value) > 1 and a.value[0] == '0':
            raise Exception("%s %r has a leading zero" % (key, a.value))


def test_wifi_stats_attribute_length(dev, apdev):
    """A maximally-configured single BSS attribute fits in 253 octets"""
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
    try:
        addr = connect_sta(dev[0], hapd, freq="5180")
        time.sleep(3)
        drive_traffic(dev[0], hapd)
        text = conn_info_raw(hapd, addr)
        logger.info("max verbosity: %d octets: %s" %
                    (len(text.encode()), text))
        # This does not reach the true worst case for a single link (roughly
        # 191 octets by independent analysis); it only proves a
        # maximally-configured single BSS still fits. The real overflow
        # vector is MLO with several links, which is out of scope here.
        if len(text.encode()) > 253:
            raise Exception("Connect-Info is %d octets, over the RADIUS "
                            "limit" % len(text.encode()))
        parse(text)
    finally:
        clear_regdom(hapd, dev)
        dev[0].dump_monitor()


def test_wifi_stats_no_extensibility_reliance(dev, apdev):
    """No emitted attribute is conformant only via the extensibility rule"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "3",
                               "wifi_stats_span": "window"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(4)
    drive_traffic(dev[0], hapd)
    text = conn_info_raw(hapd, addr)

    ci = parse(text, allow_extensibility=True)
    if ci.used_extensibility():
        raise Exception("attribute(s) parsed only via the extensibility "
                        "production: %r in %r" %
                        (ci.used_extensibility(), text))


def test_wifi_stats_query_is_nondestructive(dev, apdev):
    """Reading Connect-Info over the ctrl_iface does not reset the span"""
    # A local read is not a RADIUS signal, so it must not reset the
    # report-mode accumulator. Every other test here relies on that.
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_span": "report",
                               "wifi_stats_metric_rssi": "AVG-LIN"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(8)
    drive_traffic(dev[0], hapd)

    first = conn_info(hapd, addr).get("RSSI")
    time.sleep(0.2)
    second = conn_info(hapd, addr).get("RSSI")
    if first is None or first.span is None:
        raise Exception("no aggregated RSSI after 8s of association - the "
                        "accumulator is not accumulating")
    # An aggregated first read followed by a bare second read is itself the
    # reset: the accumulator dropped below two samples between the two calls.
    if second is None or second.span is None:
        raise Exception("the first read was aggregated and the second was "
                        "not - the ctrl_iface query reset the accumulator")

    s1 = span_seconds(first.span)
    if s1 is None:
        raise Exception("RSSI is not using a duration span despite "
                        "AVG-LIN being configured")
    s2 = span_seconds(second.span)
    if s2 is None:
        raise Exception("the span form changed between two reads 200 ms "
                        "apart: %r then %r" % (first.span, second.span))
    if s2 + 1 < s1:
        raise Exception("the span collapsed from %ds to %ds across two reads "
                        "200 ms apart - the ctrl_iface query is resetting the "
                        "accumulator" % (s1, s2))

    time.sleep(5)
    third = conn_info(hapd, addr).get("RSSI")
    s3 = span_seconds(third.span)
    if s3 is not None and s3 < s2:
        raise Exception("span shrank from %ds to %ds while the station "
                        "stayed associated" % (s2, s3))


def test_wifi_stats_algo_tokens(dev, apdev):
    """Each algorithm emits its own ALGO token and never a bare AVG"""
    for algo in ["MIN", "MAX", "AVG-LIN", "AVG-EXP"]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "4",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_metric_rssi": algo})
        try:
            addr = connect_sta(dev[0], hapd)
            time.sleep(5)
            drive_traffic(dev[0], hapd)
            text = conn_info_raw(hapd, addr)
            ci = parse(text)
            rssi = ci.get("RSSI")
            if rssi is None or rssi.algo is None:
                raise Exception("%s: RSSI carries no aggregation suffix: %s" %
                                (algo, text))
            if rssi.algo != algo:
                raise Exception("configured %s but emitted %s" %
                                (algo, rssi.algo))
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()


def test_wifi_stats_algo_values(dev, apdev):
    """MIN, MAX and AVG-LIN aggregate a driven RSSI sequence correctly"""
    # The endpoints of set_rx_rssi's valid range separate all three algorithms
    # by value: MIN and MAX land on the endpoints, AVG-LIN in between.
    levels = [-50, -30]
    expected = {"MIN": -50, "MAX": -30, "AVG-LIN": -40}
    tol = 4
    for algo in ["MIN", "MAX", "AVG-LIN"]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "10",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_metric_rssi": algo})
        try:
            addr = connect_sta(dev[0], hapd)
            for level in levels:
                set_sta_rssi(dev[0], hapd, level)
                time.sleep(2.5)
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
    """The aggregation suffix is well formed and the span is bounded"""
    for window in [1, 30, 60]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": str(window),
                                   "wifi_stats_span": "window"})
        try:
            addr = connect_sta(dev[0], hapd)
            time.sleep(min(window, 5) + 2)
            drive_traffic(dev[0], hapd)
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
                if secs > window + 1:
                    raise Exception("%s span %ds exceeds the configured "
                                    "window %ds" % (a.key, secs, window))
        finally:
            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].dump_monitor()
            hapd.disable()


def test_wifi_stats_window_digit_overflow(dev, apdev):
    """WINDOW never exceeds the three digits the ABNF allows"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "60",
                               "wifi_stats_span": "window"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(3)
    drive_traffic(dev[0], hapd)

    # WINDOW is capped at three digits while the knob accepts 3600 seconds.
    # This catches an implementation reporting the configured window; one
    # reporting the observed span cannot reach four digits without a station
    # associated for over 999 s, so the C unit tests cover the conversion.
    for window in [999, 1000, 1001, 3599, 3600]:
        if "OK" not in hapd.request("WIFI_STATS_SET_WINDOW %d" % window):
            raise Exception("failed to set window %d" % window)
        time.sleep(1.5)
        drive_traffic(dev[0], hapd)
        text = conn_info_raw(hapd, addr)
        ci = parse(text)
        for a in ci.attrs:
            if a.span is None or a.span[-1] not in "SM":
                continue
            digits = a.span[:-1]
            if len(digits) > 3:
                raise Exception("window=%d produced a %d-digit WINDOW %r, "
                                "which no conforming parser accepts: %s" %
                                (window, len(digits), a.span, text))


def test_wifi_stats_ewma_weight_form(dev, apdev):
    """AVG-EXP emits the weight form and other algorithms do not"""
    for weight in [1, 5, 9]:
        hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                                   "wifi_stats_wba_window": "4",
                                   "wifi_stats_span": "window",
                                   "wifi_stats_ewma_weight": str(weight),
                                   "wifi_stats_metric_rssi": "AVG-EXP",
                                   "wifi_stats_metric_txbitrate": "MAX"})
        try:
            addr = connect_sta(dev[0], hapd)
            time.sleep(5)
            drive_traffic(dev[0], hapd)
            text = conn_info_raw(hapd, addr)
            ci = parse(text)

            rssi = ci.get("RSSI")
            if rssi is None or rssi.algo != "AVG-EXP":
                raise Exception("weight %d: no AVG-EXP RSSI: %s" %
                                (weight, text))
            parts = rssi.span.split('-')
            if parts[0] != str(weight):
                raise Exception("emitted weight %r, configured %d" %
                                (parts[0], weight))
            if len(parts) > 1:
                # SAMPLE is milliseconds capped at three digits while the
                # collection interval is at least one second.
                if not parts[1].isdigit() or int(parts[1]) > 999:
                    raise Exception("SAMPLE %r exceeds the three digits the "
                                    "ABNF allows" % parts[1])

            # AGGR is a free union, so nothing in the grammar binds the
            # weight form to AVG-EXP; reserving it is our choice. TxBitRate is
            # configured to MAX with driven traffic, so it must be present -
            # its omission would silently skip the check.
            tx = ci.get("TxBitRate")
            if tx is None:
                raise Exception("weight %d: no TxBitRate reported despite "
                                "driven traffic: %s" % (weight, text))
            if tx.algo != "MAX":
                raise Exception("weight %d: TxBitRate emits %s, configured "
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
    """With every metric set to NONE no aggregation suffix is emitted"""
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
        raise Exception("instantaneous values must not carry an AGGR "
                        "definition: %s" % text)


def test_wifi_stats_acc_restricted(dev, apdev):
    """hostapd rejects ACC outside loss and retry"""
    # Stricter than the draft, which restricts ACC only in an ABNF comment:
    # "RSSI:-40(ACC 60S)" is grammatical. This pins hostapd's config policy.
    hapd = start_ap(apdev[0])
    for metric in ["RSSI", "TxBitRate", "RxBitRate"]:
        before = hapd.request("WIFI_STATS_GET_METRIC " + metric).strip()
        if not rejected(hapd.request("WIFI_STATS_SET_METRIC %s ACC" % metric)):
            raise Exception("ACC accepted for %s" % metric)
        after = hapd.request("WIFI_STATS_GET_METRIC " + metric).strip()
        if before != after:
            raise Exception("%s changed from %r to %r on a rejected SET" %
                            (metric, before, after))

    for metric in ["FrameLoss", "FrameRetry"]:
        if "OK" not in hapd.request("WIFI_STATS_SET_METRIC %s ACC" % metric):
            raise Exception("ACC rejected for %s" % metric)


def test_wifi_stats_default_algorithms(dev, apdev):
    """The default algorithms match the profile the draft recommends"""
    hapd = start_ap(apdev[0])
    status = wifi_stats_status(hapd)
    # draft-10 section 4.2
    if status.get("TxBitRate") != "MAX" or status.get("RxBitRate") != "MAX":
        raise Exception("bit rates default to %r/%r, not MAX" %
                        (status.get("TxBitRate"), status.get("RxBitRate")))
    if status.get("RSSI") not in ["AVG-LIN", "AVG-EXP"]:
        raise Exception("RSSI defaults to %r, not an average" %
                        status.get("RSSI"))
    for m in ["FrameLoss", "FrameRetry"]:
        if status.get(m) != "ACC":
            raise Exception("%s defaults to %r, not ACC" % (m, status.get(m)))

    # STATUS alone does not prove the formatter honours the defaults.
    addr = connect_sta(dev[0], hapd)
    time.sleep(4)
    drive_traffic(dev[0], hapd)
    ci = conn_info(hapd, addr)

    tx = ci.get("TxBitRate")
    rx = ci.get("RxBitRate")
    rssi = ci.get("RSSI")
    if tx is None or rx is None or rssi is None:
        raise Exception("bit rate or RSSI missing from the wire: %s" %
                        ci.text)
    if tx.algo != "MAX" or rx.algo != "MAX":
        raise Exception("bit rates emit %r/%r on the wire, not MAX" %
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

    def wait_for(self, status_type, count=1, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            got = self.of_type(status_type)
            if len(got) >= count:
                return got
            time.sleep(0.3)
        raise Exception("timed out waiting for %d accounting packets of type "
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
    """Accounting-Start carries a conforming Connect-Info attribute"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params())
        connect_sta(dev[0], hapd)
        start = acct.wait_for(ACCT_START)[0]

        if len(start["Connect-Info"]) != 1:
            raise Exception("expected exactly one Connect-Info, got %d" %
                            len(start["Connect-Info"]))
        text = connect_info_of(start)
        logger.info("Accounting-Start Connect-Info: %s" % text)
        ci = parse(text)
        if not [a for a in ci.attrs if a.kind == 'kv']:
            raise Exception("the WBA format did not engage: %s" % text)


def test_wifi_stats_radius_interim_and_reset(dev, apdev):
    """Report-mode spans track the reporting cadence and do not accumulate"""
    interim = 5
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_span": "report",
             "wifi_stats_metric_rssi": "AVG-LIN"},
            interim=interim))
        connect_sta(dev[0], hapd)
        # No ctrl_iface queries here; they would confound the measurement.
        interims = acct.wait_for(ACCT_INTERIM, count=3, timeout=40)

        spans = []
        for pkt in interims[:3]:
            ci = parse(connect_info_of(pkt))
            rssi = ci.get("RSSI")
            if rssi is None or rssi.span is None:
                raise Exception("interim updates carry no aggregated RSSI")
            secs = span_seconds(rssi.span)
            if secs is None:
                raise Exception("RSSI span is not a duration")
            spans.append(secs)
        logger.info("interim spans: %r" % spans)

        # Each report covers only the interval since the previous one; an
        # accumulator that never resets grows across reports instead.
        if spans[2] > spans[0] + 3:
            raise Exception("spans %r grow with each report - the accumulator "
                            "is not being reset when the report is sent" %
                            spans)
        for secs in spans:
            if secs > interim + 3:
                raise Exception("span %ds far exceeds the %ds interim "
                                "interval: %r" % (secs, interim, spans))


def test_wifi_stats_radius_window_span_independent(dev, apdev):
    """Window-mode spans are bounded by the window, not the report cadence"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_wba_window": "10",
             "wifi_stats_span": "window"}, interim=25))
        connect_sta(dev[0], hapd)
        interims = acct.wait_for(ACCT_INTERIM, count=2, timeout=90)
        for pkt in interims[:2]:
            ci = parse(connect_info_of(pkt))
            for a in ci.attrs:
                secs = span_seconds(a.span)
                if secs is not None and secs > 11:
                    raise Exception("%s span %ds exceeds the 10s sliding "
                                    "window - window mode is tracking the "
                                    "report cadence instead" % (a.key, secs))


def test_wifi_stats_radius_accounting_stop(dev, apdev):
    """Accounting-Stop still carries usable statistics"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params(
            {"wifi_stats_interval": "1", "wifi_stats_span": "report"}))
        connect_sta(dev[0], hapd)
        time.sleep(8)
        drive_traffic(dev[0], hapd)
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()

        stop = acct.wait_for(ACCT_STOP)[0]
        text = connect_info_of(stop)
        if text is None:
            raise Exception("Accounting-Stop carries no Connect-Info")
        logger.info("Accounting-Stop Connect-Info: %s" % text)
        ci = parse(text)
        # Station state torn down before the Stop is built used to produce a
        # well-formed attribute full of zeros
        rssi = ci.get("RSSI")
        if rssi is None:
            raise Exception("Accounting-Stop carries no RSSI at all - "
                            "station state was probably already gone: %s" %
                            text)
        if int(rssi.value) == 0:
            raise Exception("Accounting-Stop reports RSSI:0 - station state "
                            "was probably already gone: %s" % text)
        if ci.maxspeed is not None and ci.maxspeed == 0:
            raise Exception("Accounting-Stop reports a zero max rate: %s" %
                            text)


def test_wifi_stats_radius_legacy_fallback(dev, apdev):
    """wifi_stats_wba_enabled=0 restores the historical Connect-Info format"""
    with AcctCapture() as acct:
        hapd = start_ap(apdev[0], acct_params({"wifi_stats_wba_enabled": "0"}))
        connect_sta(dev[0], hapd)
        start = acct.wait_for(ACCT_START)[0]
        text = connect_info_of(start)
        logger.info("legacy Connect-Info: %s" % text)

        # The legacy string is deliberately not draft-conformant. This
        # guards the fallback branch's existence, not its conformance.
        for token in ["RSSI:", "TxBitRate:", "RxBitRate:", "FrameLoss:",
                      "FrameRetry:", "Global-OC:", "("]:
            if token in text:
                raise Exception("WBA token %r present with wba_enabled=0: %s" %
                                (token, text))
        if not text.startswith("CONNECT "):
            raise Exception("unexpected legacy format: %s" % text)


def test_wifi_stats_degenerate_spans(dev, apdev):
    """Zero-sample and degenerate spans still produce a conforming string"""
    cases = [
        ("no samples yet", {"wifi_stats_interval": "1",
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
    """A station rejoining with the same MAC starts a fresh span"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_span": "report"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(6)
    drive_traffic(dev[0], hapd, count=5)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    time.sleep(2)

    connect_sta(dev[0], hapd)
    time.sleep(2)
    drive_traffic(dev[0], hapd)
    text = conn_info_raw(hapd, addr)
    ci = parse(text)

    for a in ci.attrs:
        secs = span_seconds(a.span)
        if secs is not None and secs > 8:
            raise Exception("%s span %ds carries over from the previous "
                            "association: %s" % (a.key, secs, text))


def test_wifi_stats_runtime_reconfigure(dev, apdev):
    """Reconfiguration with a station associated never breaks the output"""
    hapd = start_ap(apdev[0])
    addr = connect_sta(dev[0], hapd)
    time.sleep(2)

    sequence = [
        ("WIFI_STATS_SET_INTERVAL 3600", "WIFI_STATS_GET_INTERVAL", "3600"),
        ("WIFI_STATS_SET_INTERVAL 1", "WIFI_STATS_GET_INTERVAL", "1"),
        ("WIFI_STATS_SET_WINDOW 3600", "WIFI_STATS_GET_WINDOW", "3600"),
        ("WIFI_STATS_SET_WINDOW 1", "WIFI_STATS_GET_WINDOW", "1"),
        ("WIFI_STATS_SET_WINDOW 60", "WIFI_STATS_GET_WINDOW", "60"),
        ("WIFI_STATS_SET_SPAN window", "WIFI_STATS_GET_SPAN", "window"),
        ("WIFI_STATS_SET_SPAN report", "WIFI_STATS_GET_SPAN", "report"),
        ("WIFI_STATS_SET_EWMA_WEIGHT 9", "WIFI_STATS_GET_EWMA_WEIGHT", "9"),
        ("WIFI_STATS_SET_EWMA_WEIGHT 1", "WIFI_STATS_GET_EWMA_WEIGHT", "1"),
        ("WIFI_STATS_SET_METRIC RSSI AVG-EXP",
         "WIFI_STATS_GET_METRIC RSSI", "AVG-EXP"),
        ("WIFI_STATS_SET_METRIC RSSI MIN", "WIFI_STATS_GET_METRIC RSSI",
         "MIN"),
        ("WIFI_STATS_SET_METRIC TxBitRate MAX",
         "WIFI_STATS_GET_METRIC TxBitRate", "MAX"),
    ]
    for setter, getter, expect in sequence:
        if "OK" not in hapd.request(setter):
            raise Exception("%r failed" % setter)
        got = hapd.request(getter).strip()
        if got != expect:
            raise Exception("%r returned %r, expected %r" %
                            (getter, got, expect))
        parse(conn_info_raw(hapd, addr))

    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd stopped responding")


def test_wifi_stats_config_reload(dev, apdev):
    """RELOAD re-applies wifi_stats settings to the formatting path"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "60",
                               "wifi_stats_span": "window",
                               "wifi_stats_metric_rssi": "MAX"})
    addr = connect_sta(dev[0], hapd)
    time.sleep(3)

    for cmd in ["SET wifi_stats_wba_window 5",
                "SET wifi_stats_metric_rssi MIN",
                "SET wifi_stats_ewma_weight 3"]:
        if "OK" not in hapd.request(cmd):
            raise Exception("%r failed" % cmd)
    if "OK" not in hapd.request("RELOAD"):
        raise Exception("RELOAD failed")
    hapd.wait_sta()
    time.sleep(4)
    drive_traffic(dev[0], hapd)

    status = wifi_stats_status(hapd)
    if status.get("window") != "5" or status.get("RSSI") != "MIN":
        raise Exception("RELOAD did not apply the new settings: %r" % status)

    # Reporting the new configuration is not enough; the formatter must use it.
    ci = conn_info(hapd, addr)
    rssi = ci.get("RSSI")
    if rssi is not None and rssi.algo is not None and rssi.algo != "MIN":
        raise Exception("status reports MIN but the attribute still emits "
                        "%s - the reload did not reach the formatter" %
                        rssi.algo)
    if rssi is not None:
        secs = span_seconds(rssi.span)
        if secs is not None and secs > 6:
            raise Exception("span %ds exceeds the reloaded 5s window" % secs)


def test_wifi_stats_config_invalid(dev, apdev):
    """Out-of-range and locally-disallowed config values fail at start-up"""
    # Positive control: a systemic harness failure would otherwise make
    # every row below vacuously pass at once.
    good_params = hostapd.wpa2_params(ssid="wifi-stats-good",
                                      passphrase=PASSPHRASE)
    good_params["wifi_stats_wba_window"] = "60"
    hostapd.add_ap(apdev[0], good_params)
    hostapd.remove_bss(apdev[0])

    out_of_range = [
        ("wifi_stats_interval", "0"),
        ("wifi_stats_interval", "3601"),
        ("wifi_stats_interval", "abc"),
        ("wifi_stats_wba_window", "0"),
        ("wifi_stats_wba_window", "3601"),
        ("wifi_stats_wba_enabled", "2"),
        ("wifi_stats_span", "sliding"),
        ("wifi_stats_ewma_weight", "0"),
        ("wifi_stats_ewma_weight", "10"),
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
    """Invalid ctrl_iface values are rejected without changing state"""
    hapd = start_ap(apdev[0])
    checks = [
        ("WIFI_STATS_SET_INTERVAL", "WIFI_STATS_GET_INTERVAL",
         ["0", "3601", "abc", ""]),
        ("WIFI_STATS_SET_WINDOW", "WIFI_STATS_GET_WINDOW",
         ["0", "3601", "abc", ""]),
        ("WIFI_STATS_SET_EWMA_WEIGHT", "WIFI_STATS_GET_EWMA_WEIGHT",
         ["0", "10", "abc", ""]),
        ("WIFI_STATS_SET_SPAN", "WIFI_STATS_GET_SPAN", ["sliding", ""]),
    ]
    for setter, getter, values in checks:
        before = hapd.request(getter).strip()
        for value in values:
            cmd = (setter + " " + value).strip()
            if not rejected(hapd.request(cmd)):
                raise Exception("%r was accepted" % cmd)
            after = hapd.request(getter).strip()
            if after != before:
                raise Exception("%r changed the value from %r to %r" %
                                (cmd, before, after))
    if not rejected(hapd.request("WIFI_STATS_SET_METRIC RSSI")):
        raise Exception("SET_METRIC with a missing algorithm was accepted")
    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd stopped responding")


def test_wifi_stats_multiple_sta(dev, apdev):
    """Each station gets its own well-formed, distinct Connect-Info"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1",
                               "wifi_stats_wba_window": "10",
                               "wifi_stats_span": "window"})
    addrs = []
    for d in dev[0:3]:
        addrs.append(connect_sta(d, hapd))

    # Without distinct values, an implementation sharing one set of
    # statistics across stations would look correct.
    levels = [-45, -40, -35]
    distinct = True
    try:
        for d, level in zip(dev[0:3], levels):
            set_sta_rssi(d, hapd, level)
    except HwsimSkip:
        distinct = False
    time.sleep(3)
    for d in dev[0:3]:
        drive_traffic(d, hapd)

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

    if distinct and len(reported) == 3:
        if len(set(reported.values())) == 1:
            raise Exception("all three stations report the same RSSI %r "
                            "despite being driven to %r - statistics are "
                            "not per-station" % (reported, levels))

    # Repeatedly reading one station must not disturb another's span.
    before = conn_info(hapd, addrs[1]).get("RSSI")
    for _i in range(5):
        conn_info(hapd, addrs[0])
    after = conn_info(hapd, addrs[1]).get("RSSI")
    if before is not None and after is not None and before.span and after.span:
        b, a = span_seconds(before.span), span_seconds(after.span)
        if b is not None and a is not None and a + 2 < b:
            raise Exception("reading one station shortened another's span "
                            "from %ds to %ds" % (b, a))


def test_wifi_stats_oom(dev, apdev):
    """Allocation failures degrade without taking hostapd down"""
    hapd = start_ap(apdev[0], {"wifi_stats_interval": "1"})
    with alloc_fail(hapd, 1, "wifi_stats_sta_buf_alloc"):
        connect_sta(dev[0], hapd)
        wait_fail_trigger(hapd, "GET_ALLOC_FAIL",
                          note="wifi_stats_sta_buf_alloc failure not triggered")
        res = hapd.request("WIFI_STATS_CONNECT_INFO " + dev[0].own_addr())
        if not res.startswith("FAIL") and not is_valid(res.strip()):
            raise Exception("a half-built attribute was returned under OOM: "
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
    """Malformed station arguments fail cleanly and leave hostapd alive"""
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
