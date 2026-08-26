#!/usr/bin/env python3
#
# Strict validator for the RADIUS Connect-Info attribute syntax defined by
# draft-grayson-connectinfo-10 (Figure 4).
# Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.
#
# The extensibility production (keyValueAttribute =/ 1*NO-DELIM-COLON ":"
# *SP 1*NO-DELIM-COLON) excludes only space, slash and colon, so "RSSI:garbage"
# and "Channel:0" both parse under the full grammar and conformance becomes
# nearly unfalsifiable. This validator therefore defaults to
# allow_extensibility=False and always holds a recognised key to its own
# production.
#
# ABNF literals are case-insensitive without an RFC 7405 "%s" prefix (RFC 5234
# section 2.3), which draft-10 never uses, so "connect 11.00 mbps" conforms and
# is accepted. Parsed tokens are normalised to the draft's canonical spelling.

import re
import sys

# Alternations are ordered longest-first: ABNF alternation is unordered but
# Python's is leftmost-first, so "[1-9]" first would match the "1" of "149".
_MAXSPEED = r'(?:[1-9][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])\.[0-9]{2}'
_RATE = r'(?:[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])(?:\.[0-9])?'
_SS = r'-?(?:1[0-9]{2}|[1-9][0-9]|[0-9])'
_CHANNUM = r'(?:2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])'
_GOC = r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])'
_PCT = r'(?:100|[1-9][0-9]|[0-9])'
_WINDOW = r'(?:[1-9][0-9]{2}|[1-9][0-9]|[0-9])[SM]'
_WEIGHT = r'[1-9]'
_SAMPLE = r'(?:[1-9][0-9]{2}|[1-9][0-9]|[0-9])'
_ALGO = r'(?:MIN|MAX|AVG-LIN|AVG-EXP|ACC)'
_AMENDMENT = r'(?:ac|ax|be|b|g|a|n)'

# AGGR = ALGO SP ( WINDOW / (WEIGHT ["-" SAMPLE]) ); SP is %x20, singular.
_AGGR = r'(?P<algo>' + _ALGO + r') (?P<span>' + _WINDOW + \
        r'|' + _WEIGHT + r'(?:-' + _SAMPLE + r')?)'

# DELIMITER = SLASH / 1*SP ; SLASH = *SP %x2F *SP
_DELIMITER = r'(?: *\/ *| +)'

# Values whose production permits a trailing ["(" AGGR ")"].
_AGGR_KEYS = {
    'RSSI': _SS,
    'TxBitRate': _RATE,
    'RxBitRate': _RATE,
    'FrameLoss': _PCT,
    'FrameRetry': _PCT,
}
# Global-OC has no AGGR option in its production.
_PLAIN_KEYS = {
    'Global-OC': _GOC,
}

_NO_DELIM_COLON = r'[\x21-\x2e\x30-\x39\x3b-\x7e]'
_EXT = r'(?P<key>' + _NO_DELIM_COLON + r'+):(?P<val> *' + \
       _NO_DELIM_COLON + r'+)'


class ConnectInfoError(Exception):
    def __init__(self, msg, text, offset):
        super().__init__("%s at offset %d: %r<<HERE>>%r" %
                         (msg, offset, text[:offset], text[offset:]))


class Attribute:
    """kind is 'legacy', 'channel' or 'kv'."""

    def __init__(self, kind, key, value, algo=None, span=None, via_ext=False):
        self.kind = kind
        self.key = key
        self.value = value
        self.algo = algo
        self.span = span
        self.via_ext = via_ext

    def key_tuple(self):
        return (self.kind, self.key, self.value, self.algo, self.span)

    def __repr__(self):
        agg = "(%s %s)" % (self.algo, self.span) if self.algo else ""
        return "<%s %s=%s%s%s>" % (self.kind, self.key, self.value, agg,
                                   " ext" if self.via_ext else "")


class ConnectInfo:
    def __init__(self, text):
        self.text = text
        self.attrs = []
        self.maxspeed = None
        self.amendment = None
        self.channel = None

    def get(self, key):
        for a in self.attrs:
            if a.key == key:
                return a
        return None

    def count(self, key):
        return len([a for a in self.attrs if a.key == key])

    def used_extensibility(self):
        return [a for a in self.attrs if a.via_ext]

    def decomposition(self):
        return [a.key_tuple() for a in self.attrs]


class _Parser:
    def __init__(self, text, allow_extensibility):
        self.t = text
        self.i = 0
        self.ext_ok = allow_extensibility
        self.out = ConnectInfo(text)

    def _fail(self, msg):
        raise ConnectInfoError(msg, self.t, self.i)

    def _match(self, pattern, fold=True):
        # fold=False is for patterns built only from the NO-DELIM-COLON byte
        # range, which is a character class rather than an ABNF literal.
        m = re.compile(pattern, re.IGNORECASE if fold else 0).match(self.t,
                                                                    self.i)
        if m:
            self.i = m.end()
        return m

    def _startswith_fold(self, literal):
        return self.t[self.i:self.i + len(literal)].lower() == literal.lower()

    def _at_boundary(self):
        if self.i >= len(self.t):
            return True
        return self.t[self.i] in ' /'

    def parse(self):
        if not self._match(r'CONNECT'):
            self._fail("does not start with CONNECT")

        self._parse_legacy_attributes()

        seen_channel = False
        while self.i < len(self.t):
            if not self._match(_DELIMITER):
                self._fail("expected a delimiter between attributes")
            if self.i >= len(self.t):
                self._fail("trailing delimiter with no attribute")
            if self._startswith_fold('Channel:') and \
               not (seen_channel and self.ext_ok):
                if seen_channel:
                    # legacyChannelNum has one slot, but extensibility
                    # absorbs a second "Channel:", so at most one is a
                    # strict-mode policy rather than a grammar rule.
                    self._fail("Channel appears more than once (strict-mode "
                               "policy; the full grammar accepts the second "
                               "via the extensibility production at draft "
                               "line 317)")
                seen_channel = True
                self._parse_channel()
            else:
                self._parse_key_value()
        return self.out

    def _parse_legacy_attributes(self):
        # legacyAttributes = 1*SP MAXSPEED " Mbps" DELIMITER WIFIAMENDMENT
        # Optional as a whole, but atomic: neither half may appear alone.
        save = self.i
        if not self._match(r' +'):
            return
        m = self._match(r'(?P<v>' + _MAXSPEED + r') Mbps')
        if not m:
            self.i = save
            return
        maxspeed = m.group('v')
        if not self._match(_DELIMITER):
            self._fail("MAXSPEED not followed by a delimiter and amendment")
        am = self._match(r'802\.11(?P<a>' + _AMENDMENT + r')')
        if not am:
            self._fail("MAXSPEED present without a valid WIFIAMENDMENT")
        if not self._at_boundary():
            self._fail("trailing characters after the 802.11 amendment")
        self.out.maxspeed = float(maxspeed)
        # AMENDMENT folds, so normalise to the draft's own spelling.
        self.out.amendment = am.group('a').lower()
        self.out.attrs.append(Attribute('legacy', 'MAXSPEED', maxspeed))
        self.out.attrs.append(Attribute('legacy', 'WIFIAMENDMENT',
                                        self.out.amendment))

    def _parse_channel(self):
        self.i += len('Channel:')
        self._match(r' *')
        m = self._match(r'(?P<v>' + _CHANNUM + r')')
        if not m or not self._at_boundary():
            self._fail("Channel value is not a valid CHANNUM (1-249)")
        self.out.channel = int(m.group('v'))
        self.out.attrs.append(Attribute('channel', 'Channel', m.group('v')))

    def _parse_key_value(self):
        for key, value_re in list(_AGGR_KEYS.items()) + list(_PLAIN_KEYS.items()):
            # Key names are ABNF literals and so fold; "rssi:garbage" must
            # reach the RSSI production and fail there rather than escaping
            # into the extensibility catch-all as a vendor attribute.
            if not self._startswith_fold(key + ':'):
                continue
            self.i += len(key) + 1
            self._match(r' *')
            m = self._match(r'(?P<v>' + value_re + r')')
            if not m:
                self._fail("%s value does not match its production" % key)
            value = m.group('v')
            algo = span = None
            if self.i < len(self.t) and self.t[self.i] == '(':
                if key in _PLAIN_KEYS:
                    self._fail("%s must not carry an aggregation suffix" % key)
                self.i += 1
                a = self._match(_AGGR)
                if not a:
                    self._fail("malformed AGGR for %s" % key)
                # ALGO and TIMEUNIT fold; hand the caller canonical case.
                algo = a.group('algo').upper()
                span = a.group('span').upper()
                if not self._match(r'\)'):
                    self._fail("unterminated aggregation suffix for %s" % key)
            if not self._at_boundary():
                self._fail("trailing characters after the %s value" % key)
            self.out.attrs.append(Attribute('kv', key, value, algo, span))
            return

        # Not a recognised key: only the extensibility production remains.
        # NO-DELIM-COLON is a byte range, not a literal, so it does not fold.
        if not self.ext_ok:
            m = re.compile(_NO_DELIM_COLON + r'+').match(self.t, self.i)
            name = m.group(0) if m else self.t[self.i:]
            self._fail("unrecognised attribute %r and extensibility is "
                       "disabled" % name)
        m = self._match(_EXT, fold=False)
        if not m or not self._at_boundary():
            self._fail("not a valid keyValueAttribute")
        self.out.attrs.append(Attribute('kv', m.group('key'),
                                        m.group('val').lstrip(),
                                        via_ext=True))


def parse(text, allow_extensibility=False):
    """Raises ConnectInfoError on any deviation from Figure 4. Recognised keys
    are always held to their own production; allow_extensibility governs only
    unrecognised keys. Literals are matched case-insensitively per RFC 5234
    section 2.3, and the decomposition is returned in canonical case."""
    if not isinstance(text, str):
        text = text.decode('utf-8')
    if len(text.encode('utf-8')) > 253:
        raise ConnectInfoError("attribute exceeds the 253-octet RADIUS limit",
                               text, 253)
    for ch in text:
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            raise ConnectInfoError("control character in attribute", text,
                                   text.index(ch))
    if text != text.strip():
        raise ConnectInfoError("leading or trailing whitespace", text, 0)
    return _Parser(text, allow_extensibility).parse()


def is_valid(text, allow_extensibility=False):
    try:
        parse(text, allow_extensibility)
        return True
    except ConnectInfoError:
        return False


# Figures 5 and 6 of the draft, unwrapped. These pin the validator itself: a
# rejection here means the validator is wrong, not the implementation.
DRAFT_EXAMPLES = [
    "CONNECT 11.00 Mbps 802.11b",
    "CONNECT 54.00 Mbps / 802.11n / RSSI: 53 / Channel: 1",
    "CONNECT 54.00 Mbps / 802.11n / Channel: 1 / RSSI: 53",
    "CONNECT 400.00 Mbps 802.11ac Channel:44 RSSI:50",
    "CONNECT RSSI:56 TxBitRate:150.0 RxBitRate:150.0 Global-OC:116",
    "CONNECT 400.00 Mbps 802.11ax RSSI:56 TxBitRate:150.0 "
    "RxBitRate:150.0 Global-OC:133",
    "CONNECT RSSI:56(AVG-LIN 10M) TxBitRate:150.0(MAX 10M) "
    "RxBitRate:150.0(MAX 10M)",
    "CONNECT 400.00 Mbps 802.11ac RSSI:56(AVG-LIN 600S) "
    "TxBitRate:150.0(MAX 600S) RxBitRate:150.0(MAX 600S) "
    "FrameLoss:3(ACC 60S) FrameRetry:6(ACC 60S)",
    "CONNECT TxBitRate:150.0(MAX 30S) RxBitRate:120.5(MAX 30S) "
    "RSSI:-65(AVG-EXP 6-100) FrameLoss:2(ACC 30S) FrameRetry:4(ACC 30S) "
    "Global-OC:133",
    # Case-varied forms of the above, conforming per RFC 5234 section 2.3.
    "connect 11.00 mbps 802.11b",
    "CONNECT RSSI:56(avg-lin 10m) TxBitRate:150.0(max 10m) "
    "RxBitRate:150.0(MAX 10M)",
    "connect 400.00 mbps 802.11AC channel: 44 rssi:50 global-oc:116",
]

# Strings no parse of Figure 4 accepts, in any mode, each naming the production
# it violates. A rejection here indicts the string.
DRAFT_COUNTEREXAMPLES = [
    ("CONNECT 54.0 Mbps 802.11n", "MAXSPEED needs two fractional digits"),
    ("CONNECT 54 Mbps 802.11n", "MAXSPEED needs a fractional part"),
    ("CONNECT 054.00 Mbps 802.11n", "MAXSPEED has a leading zero"),
    ("CONNECT 54.00 Mbps", "MAXSPEED without WIFIAMENDMENT"),
    ("CONNECT 54.00Mbps 802.11n", "no space before Mbps"),
    ("CONNECT 54.00 Mbps 802.11ah", "unknown amendment"),
    # legacyAttributes joins "CONNECT" with 1*SP, not DELIMITER, so this is
    # the one top-level join at which a slash does not parse.
    ("CONNECT / 54.00 Mbps 802.11n", "slash before MAXSPEED"),
    # RFC 2869 permits "<tx>/<rx> Mbps"; MAXSPEED is singular and cannot
    # express it. The draft's own backwards-compatibility gap, not an AP's.
    ("CONNECT 54.00/28.80 Mbps 802.11n", "RFC 2869 dual-speed slash form"),
    ("CONNECT RSSI:-40(AVG 30S)", "bare AVG is not an ALGO"),
    ("CONNECT RSSI:-40 (MAX 30S)", "space before the aggregation suffix"),
    ("CONNECT RSSI:-40(MAX  30S)", "two spaces inside AGGR"),
    ("CONNECT RSSI:56(MAX 6 - 100)", "spaces around the SAMPLE hyphen"),
    ("CONNECT RSSI:56(MAX 60S", "unterminated aggregation suffix"),
    ("CONNECT Global-OC:81(MAX 30S)", "Global-OC takes no AGGR"),
    ("CONNECT RSSI:-40(MAX 1000S)", "WINDOW above three digits"),
    ("CONNECT RSSI:-40(AVG-EXP 0)", "WEIGHT must be non-zero"),
    ("CONNECT RSSI:-40(AVG-EXP 6-1000)", "SAMPLE above three digits"),
    ("CONNECT RSSI:-40(MAX 30)", "WINDOW without a TIMEUNIT"),
    ("NOTCONNECT RSSI:-40", "does not start with CONNECT"),
]

# Strings the full grammar ACCEPTS - the extensibility production at draft
# line 317 excludes only space, slash and colon, so any colon-bearing token
# free of those three parses as a vendor keyValueAttribute no matter what it
# says. This validator rejects them anyway, because holding a recognised key
# to its own production is the only way conformance to this draft is
# falsifiable at all. A rejection here indicts nothing: it reports that the
# value would not have satisfied the key's own production had the key been
# read as the draft's own attribute rather than as a vendor extension.
STRICT_POLICY_REJECTIONS = [
    ("CONNECT RSSI:-200", "SS magnitude above 199"),
    ("CONNECT RSSI:-05", "SS with a leading zero"),
    ("CONNECT TxBitRate:150.00", "RATE with two fractional digits"),
    ("CONNECT FrameLoss:101", "PCT above 100"),
    ("CONNECT FrameLoss:07", "PCT with a leading zero"),
    ("CONNECT FrameLoss:-3", "negative PCT"),
    ("CONNECT Channel:0", "CHANNUM has no zero alternative"),
    ("CONNECT Channel:250", "CHANNUM above 249"),
    ("CONNECT Global-OC:0", "GOC has no zero alternative"),
    ("CONNECT Global-OC:256", "GOC above 255"),
    # The only aggregation-punctuation error with no space in it, and so the
    # only one the catch-all can absorb; every other one in the list above is
    # split by a space into a token with no colon.
    ("CONNECT RSSI:56(MAX60S)", "no space between ALGO and its operand"),
    # legacyChannelNum has one slot, but the second instance is an ordinary
    # keyValueAttribute. This is the one entry the validator also accepts
    # under allow_extensibility=True.
    ("CONNECT Channel:1 Channel:2", "Channel appears more than once"),
]


def _self_test():
    ok = True

    def fail(msg):
        nonlocal ok
        ok = False
        print("FAIL %s" % msg)

    for text in DRAFT_EXAMPLES:
        try:
            parse(text)
        except ConnectInfoError as e:
            fail("(conforming example rejected): %s" % e)

    for text, why in DRAFT_COUNTEREXAMPLES:
        if is_valid(text):
            fail("(grammar violation accepted: %s): %r" % (why, text))
        elif is_valid(text, allow_extensibility=True):
            fail("(classified as a grammar violation but the extensibility "
                 "production accepts it, so it belongs in "
                 "STRICT_POLICY_REJECTIONS: %s): %r" % (why, text))

    for text, why in STRICT_POLICY_REJECTIONS:
        if is_valid(text):
            fail("(strict policy did not reject: %s): %r" % (why, text))

    # The conforming examples must not need the extensibility production.
    for text in DRAFT_EXAMPLES:
        try:
            a = parse(text, allow_extensibility=False)
            b = parse(text, allow_extensibility=True).decomposition()
            if a.decomposition() != b:
                fail("(decomposition differs with extensibility): %r" % text)
            if a.used_extensibility():
                fail("(parsed via the extensibility production): %r" % text)
        except ConnectInfoError as e:
            fail(": %s" % e)

    # T-28: a receiver built to Figure 4 accepts any casing, because RFC 5234
    # literals are case-insensitive and the draft uses no "%s". This asserts
    # nothing about a generator - emitting canonical uppercase is a free
    # choice and asserting it would be over-fitting.
    for text in DRAFT_EXAMPLES:
        try:
            want = parse(text).decomposition()
        except ConnectInfoError:
            continue
        for variant in [text.lower(), text.upper()]:
            try:
                got = parse(variant).decomposition()
            except ConnectInfoError as e:
                fail("(case variant of a conforming string rejected): %s" % e)
                continue
            if got != want:
                fail("(case variant decomposes differently): %r vs %r" %
                     (variant, text))

    print("self-test: %s (%d conforming examples, %d grammar "
          "counterexamples, %d strict-policy rejections)" %
          ("PASS" if ok else "FAIL", len(DRAFT_EXAMPLES),
           len(DRAFT_COUNTEREXAMPLES), len(STRICT_POLICY_REJECTIONS)))
    return 0 if ok else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--self-test':
        return _self_test()
    if len(sys.argv) > 1:
        texts = sys.argv[1:]
    else:
        texts = [line.rstrip('\n') for line in sys.stdin if line.strip()]
    rc = 0
    for text in texts:
        try:
            ci = parse(text)
            print("OK   %r" % text)
            for a in ci.attrs:
                print("       %r" % a)
        except ConnectInfoError as e:
            rc = 1
            print("FAIL %s" % e)
    return rc


if __name__ == '__main__':
    sys.exit(main())
