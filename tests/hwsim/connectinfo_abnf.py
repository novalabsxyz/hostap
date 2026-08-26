#!/usr/bin/env python3
#
# Strict validator for the RADIUS Connect-Info attribute syntax defined by
# draft-ietf-radext-connectinfo-02 (Figure 4).
# Copyright (c) 2026, Iegor Sergieienkov <iegor@nova-labs.com>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import re
import sys

# Recognized keys are always held to their own production: through the
# extensibility production "RSSI:garbage" and "Channel:0" would parse as
# vendor attributes. Literals are matched case-insensitively (RFC 5234,
# section 2.3) and returned in the draft's spelling.

# Alternations are ordered longest-first: ABNF alternation is unordered but
# Python's is leftmost-first, so "[1-9]" first would match the "1" of "149".
_MAXSPEED = r'(?:[1-9][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])\.[0-9]{2}'
_RATE = r'(?:[1-9][0-9]{4}|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])(?:\.[0-9])?'
_SS = r'-?(?:1[0-9]{2}|[1-9][0-9]|[0-9])'
_CHANNUM = r'(?:2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])'
_GOC = r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])'
_PCT = r'(?:100|[1-9][0-9]|[0-9])'
_WINDOW = r'(?:[1-9][0-9]{2}|[1-9][0-9]|[0-9])[SM]'
_WEIGHT = r'[1-9]'
_SAMPLE = r'(?:[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])'
_ALGO = r'(?:MIN|MAX|AVG-LIN|AVG-EXP|ACC)'
# The draft's b/g/a/n/ac/ax/be is read as open, not closed: it already omits
# ad, af, ah and ay, and bn is next. Any one- or two-letter designator passes.
_AMENDMENT = r'[a-z]{1,2}'
_LINKID = r'(?:1[0-5]|[0-9])'

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
# Global-OC has no AGGR option; its only suffix is ["(Link-ID:" LINKID ")"].
_LINK_ID_KEYS = {
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

    def __init__(self, kind, key, value, algo=None, span=None, via_ext=False,
                 link_id=None):
        self.kind = kind
        self.key = key
        self.value = value
        self.algo = algo
        self.span = span
        self.via_ext = via_ext
        self.link_id = link_id

    def key_tuple(self):
        return (self.kind, self.key, self.value, self.algo, self.span,
                self.link_id)

    def __repr__(self):
        agg = "(%s %s)" % (self.algo, self.span) if self.algo else ""
        link = "(Link-ID:%d)" % self.link_id if self.link_id is not None \
            else ""
        return "<%s %s=%s%s%s%s>" % (self.kind, self.key, self.value, agg,
                                     link, " ext" if self.via_ext else "")

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

    def all(self, key):
        return [a for a in self.attrs if a.key == key]

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
                               "via the extensibility production)")
                seen_channel = True
                self._parse_channel()
            else:
                self._parse_key_value()
        if not self.ext_ok:
            self._check_link_ids()
        return self.out

    def _check_link_ids(self):
        # The draft never makes a per-link Link-ID mandatory or unique, but
        # without both a receiver cannot map classes to links; strict mode
        # requires them.
        gocs = self.out.all('Global-OC')
        if len(gocs) < 2:
            return
        ids = [a.link_id for a in gocs]
        if None in ids:
            self._fail("several Global-OC without a Link-ID on each "
                       "(strict-mode policy)")
        if len(set(ids)) != len(ids):
            self._fail("several Global-OC with a repeated Link-ID "
                       "(strict-mode policy)")

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
        # AMENDMENT folds, so normalize to the draft's own spelling.
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
        for key, value_re in list(_AGGR_KEYS.items()) + list(_LINK_ID_KEYS.items()):
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
            algo = span = link_id = None
            if self.i < len(self.t) and self.t[self.i] == '(' and \
               key in _LINK_ID_KEYS:
                ln = self._match(r'\(Link-ID:(?P<l>' + _LINKID + r')\)')
                if not ln:
                    self._fail("%s suffix is not (Link-ID:0-15)" % key)
                link_id = int(ln.group('l'))
            elif self.i < len(self.t) and self.t[self.i] == '(':
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
            self.out.attrs.append(Attribute('kv', key, value, algo, span,
                                            link_id=link_id))
            return

        # Not a recognized key: only the extensibility production remains.
        # NO-DELIM-COLON is a byte range, not a literal, so it does not fold.
        if not self.ext_ok:
            m = re.compile(_NO_DELIM_COLON + r'+').match(self.t, self.i)
            name = m.group(0) if m else self.t[self.i:]
            self._fail("unrecognized attribute %r and extensibility is "
                       "disabled" % name)
        m = self._match(_EXT, fold=False)
        if not m or not self._at_boundary():
            self._fail("not a valid keyValueAttribute")
        self.out.attrs.append(Attribute('kv', m.group('key'),
                                        m.group('val').lstrip(),
                                        via_ext=True))

def parse(text, allow_extensibility=False):
    """Raises ConnectInfoError on any deviation from Figure 4. Recognized keys
    are always held to their own production; allow_extensibility governs only
    unrecognized keys. Literals are matched case-insensitively per RFC 5234
    section 2.3, and the decomposition is returned in canonical case."""
    if not isinstance(text, str):
        text = text.decode('utf-8')
    if len(text.encode('utf-8')) > 253:
        raise ConnectInfoError("attribute exceeds the 253-octet RADIUS limit",
                               text, 253)
    for ch in text:
        if ord(ch) < 0x20 or ord(ch) > 0x7e:
            raise ConnectInfoError("control or non-ASCII character in "
                                   "attribute", text,
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

# Figures 5 and 6 of the draft, unwrapped, with their case-varied forms. These
# pin the validator itself: a rejection here means the validator is wrong, not
# the implementation.
DRAFT_EXAMPLES = [
    "CONNECT 54.00 Mbps / 802.11n / Channel: 1 / RSSI: 53",
    "CONNECT 400.00 Mbps 802.11ac Channel:44 RSSI:50",
    "CONNECT RSSI:56 TxBitRate:150.0 RxBitRate:150.0 Global-OC:116",
    "CONNECT 400.00 Mbps 802.11ax RSSI:56 TxBitRate:150.0 "
    "RxBitRate:150.0 Global-OC:133(Link-ID:0)",
    "CONNECT RSSI:56(AVG-LIN 10M) TxBitRate:150.0(MAX 10M) "
    "RxBitRate:150.0(MAX 10M)",
    "CONNECT 400.00 Mbps 802.11ac RSSI:56(AVG-LIN 600S) "
    "TxBitRate:150.0(MAX 600S) RxBitRate:150.0(MAX 600S) "
    "FrameLoss:3(ACC 60S) FrameRetry:6(ACC 60S)",
    "CONNECT TxBitRate:150.0(MAX 30S) RxBitRate:120.5(MAX 30S) "
    "RSSI:-65(AVG-EXP 6-100) FrameLoss:2(ACC 30S) FrameRetry:4(ACC 30S) "
    "Global-OC:133(Link-ID:0)",
    # Case-varied forms of the above, conforming per RFC 5234 section 2.3.
    "connect 11.00 mbps 802.11b",
    "CONNECT RSSI:56(avg-lin 10m) TxBitRate:150.0(max 10m) "
    "RxBitRate:150.0(MAX 10M)",
    "connect 400.00 mbps 802.11AC channel: 44 rssi:50 global-oc:116",
]

# Conforming strings for productions the figures leave at one value.
EXTRA_EXAMPLES = [
    # section 3 examples, not in Figures 5 and 6
    "CONNECT 11.00 Mbps 802.11b",
    "CONNECT 54.00 Mbps / 802.11n / RSSI: 53 / Channel: 1",
    # the largest MAXSPEED and the longest attribute RADIUS carries
    "CONNECT 99999.99 Mbps 802.11bn",
    "CONNECT" + "".join(" Global-OC:81(Link-ID:%d)" % i for i in range(9)) +
    " TxBitRate:150.0 RxBitRate:5.0",
    "CONNECT RSSI:-40(AVG-EXP 6-1000)",
    "CONNECT RSSI:-40(AVG-EXP 9-9999)",
    "CONNECT TxBitRate:46117.6(MAX 30S) RxBitRate:99999.9",
    "CONNECT 46117.65 Mbps 802.11be Global-OC:137(Link-ID:15)",
    "CONNECT 46117.65 Mbps 802.11bn",
    "CONNECT 6756.75 Mbps 802.11ad",
    "CONNECT 2882.35 Mbps 802.11be Channel:37 Global-OC:137(Link-ID:2) "
    "Global-OC:128(Link-ID:1) Global-OC:84(Link-ID:0)",
]

# Strings no parse of Figure 4 accepts, in any mode, each naming the production
# it violates. A rejection here indicts the string.
DRAFT_COUNTEREXAMPLES = [
    ("CONNECT 54.0 Mbps 802.11n", "MAXSPEED needs two fractional digits"),
    ("CONNECT 54 Mbps 802.11n", "MAXSPEED needs a fractional part"),
    ("CONNECT 054.00 Mbps 802.11n", "MAXSPEED has a leading zero"),
    ("CONNECT 54.00 Mbps", "MAXSPEED without WIFIAMENDMENT"),
    ("CONNECT 100000.00 Mbps 802.11be", "MAXSPEED above five integer digits"),
    ("CONNECT" + "".join(" Global-OC:81(Link-ID:%d)" % i for i in range(9)) +
     " TxBitRate:150.0 RxBitRate:15.0", "254 octets, over the RADIUS limit"),
    ("CONNECT 54.00Mbps 802.11n", "no space before Mbps"),
    ("CONNECT 54.00 Mbps 802.11", "amendment with no letters"),
    ("CONNECT 54.00 Mbps 802.11abc", "amendment of three letters"),
    ("CONNECT 54.00 Mbps 802.11b3", "amendment with a digit"),
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
    ("CONNECT RSSI:-40(AVG-EXP 6-10000)", "SAMPLE above four digits"),
    ("CONNECT Global-OC:133(Link-ID:16)", "LINKID above 15"),
    ("CONNECT Global-OC:133(Link-ID:)", "empty LINKID"),
    ("CONNECT RSSI:-50(Link-ID:0)", "RSSI takes no Link-ID"),
    ("CONNECT Global-OC:133(Link-ID:0)(MAX 30S)", "Global-OC takes no AGGR"),
    ("CONNECT RSSI:-40(MAX 30)", "WINDOW without a TIMEUNIT"),
    ("NOTCONNECT RSSI:-40", "does not start with CONNECT"),
    # U+017F folds to s and U+212A to k under a Unicode case-insensitive
    # match; the grammar is %x20-7e only.
    ("CONNECT RSSI:56(MAX 10\u017f)", "non-ASCII TIMEUNIT"),
    ("CONNECT 54.00 Mbp\u017f 802.11n", "non-ASCII in the Mbps literal"),
]

# Strings the full grammar accepts through the extensibility production, as
# any token with a colon and no space or slash is a valid vendor attribute.
# Strict mode rejects them because a recognized key is held to its own
# production.
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
    ("CONNECT TxBitRate:100000.0", "RATE above five integer digits"),
    ("CONNECT Global-OC:133(Link-ID=0)", "Link-ID with '=' not ':'"),
    ("CONNECT Global-OC:133 (Link-ID:0)", "space before the Link-ID suffix"),
    ("CONNECT Global-OC:116 Global-OC:133",
     "several Global-OC, none with a Link-ID"),
    ("CONNECT Global-OC:116(Link-ID:0) Global-OC:133",
     "several Global-OC, one without a Link-ID"),
    ("CONNECT Global-OC:116(Link-ID:1) Global-OC:133(Link-ID:1)",
     "several Global-OC with the same Link-ID"),
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

    for text in DRAFT_EXAMPLES + EXTRA_EXAMPLES:
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
    for text in DRAFT_EXAMPLES + EXTRA_EXAMPLES:
        try:
            a = parse(text, allow_extensibility=False)
            b = parse(text, allow_extensibility=True).decomposition()
            if a.decomposition() != b:
                fail("(decomposition differs with extensibility): %r" % text)
            if a.used_extensibility():
                fail("(parsed via the extensibility production): %r" % text)
        except ConnectInfoError as e:
            fail(": %s" % e)

    # Literals are case-insensitive (RFC 5234, section 2.3), so every case
    # variant of a conforming string has to parse to the same decomposition.
    for text in DRAFT_EXAMPLES + EXTRA_EXAMPLES:
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
          ("PASS" if ok else "FAIL",
           len(DRAFT_EXAMPLES) + len(EXTRA_EXAMPLES),
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
