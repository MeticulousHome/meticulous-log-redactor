"""Redaction rules for machine_logs.txt before it leaves the device.

Scope: the must-redact set only (SSID, BSSID/MACs, IPv6, credentials including
pairing codes and bearer tokens, and IANA timezone). Tier-2 identifiers
(serial, hostname, hawkbit ID) are deliberately NOT touched -- support needs
them, and they are covered by retention policy rather than by this filter.

Rule order is load-bearing; see RULES below.

This is the only copy. meticulous-watcher drives it at read time, when a bug
report is built; meticulous-backend drives it at emit time from a logging
filter. Both consume this repository as a submodule checked out at
``log_redactor/``, and both load the same per-device key, so a value gets the
same token in either service -- that correspondence is the whole reason the
module is shared rather than reimplemented.

Consequences of being shared, all of them load-bearing:

* Nothing service-specific belongs here. A rule that only makes sense for one
  consumer breaks the correspondence for the other.
* Formatting is owned by this repository (black, line length 96). Consumers
  exclude this directory from their own formatters. They previously did not,
  which is how two copies of this file silently diverged.
* ``tests/test_redaction_contract.py`` pins the exact token strings for a fixed
  key. It runs here and in both consumers, against the commit they have checked
  out. Never update its expected values to make it pass.
"""

import hashlib
import hmac
import os
import re

REDACTED = "[REDACTED]"
DEFAULT_KEY_PATH = "/root/.redaction_key"
KEY_SIZE = 32

# MACs that identify no one -- keep them, they carry diagnostic signal.
MAC_ALLOWLIST = re.compile(
    r"^(?:ff:ff:ff:ff:ff:ff|00:00:00:00:00:00|33:33:[0-9a-f:]+|01:00:5e:[0-9a-f:]+)$",
    re.IGNORECASE,
)

# An SSID shorter than this is not literal-swept in pass 2 -- too likely to
# collide with ordinary log text ("up", "ok"). Anchored hits still redact.
MIN_SWEEP_LEN = 4

# NetworkManager logs non-wifi connections with the same "connection '<name>'"
# wording as wifi ones. These are interface names, not user network names.
# Anything NOT on this list is still redacted -- over-redaction is the safe
# direction for a field that holds arbitrary user text.
CONNECTION_ALLOWLIST = re.compile(r"^(?:lo|usb\d+|eth\d+|Wired connection \d+)$", re.IGNORECASE)


def _pseudonym(kind, value, key):
    """Stable per-device pseudonym.

    Uses HMAC-SHA256 to guarantee that `same value -> same token` within one
    device's reports, so an engineer can still see "the MAC changed at this
    boot" or "same AP as last report".

    Different device -> different token, so reports cannot be joined across the
    fleet. That unlinkability is what REDACTION_SPEC.md and the privacy notice
    claim, so it is a property to preserve, not an implementation detail.

    Note: the stability of the pseudonymisation depends on the key being stable
    within the device. Never used for credentials.
    """
    digest = hmac.new(key, f"{kind}\0{value}".encode(), hashlib.sha256)
    # Underscore, NOT colon. "[SSID:abcd1234]" is itself a key:value shape and
    # the unquoted `ssid:` rule below happily matched inside it, learning the
    # hash as if it were a network name. An underscore keeps \bssid\b from
    # ever landing next to a separator.
    return f"[{kind}_{digest.hexdigest()[:8]}]"


def pseudonym(kind, value, key):
    """Public entry point for call sites that pseudonymise at source.

    The backend's wifi.redact_ssid() uses this so a value it already knows gets
    exactly the token this module would have produced for it, which is what lets
    an occurrence in a backend log line be matched up with the same network in a
    NetworkManager line.
    """
    return _pseudonym(kind, value, key)


class RedactionState:
    """Block tracking that survives across calls to redact().

    The backend feeds redact() one log record at a time, but the config YAML
    dump arrives as one record per line, so the KnownWifis indentation tracking
    has to persist between calls or the block is never recognised.

    Learned SSIDs deliberately do NOT live here. In a whole-file pass the
    literal sweep is bounded to one report, but on an always-on emit filter a
    network named "Home" or "Test" would tokenise that word in every later log
    line for the life of the process. Learning stays per-call.
    """

    __slots__ = ("known_wifis_indent", "ssid_key_indent")

    def __init__(self):
        self.known_wifis_indent = None
        self.ssid_key_indent = None


# --------------------------------------------------------------------------
# Rule 1 -- credentials.  Runs FIRST so a password that happens to look like
# a MAC or an SSID is destroyed outright rather than pseudonymised.
# --------------------------------------------------------------------------

# Key must sit immediately against the separator. This is what stops the rule
# eating "Password already set: True" and "password changed for root".
_CRED_KEY = (
    r"root_?password|ap_?password|passwd|password|passphrase"
    r"|psk|pre_?shared_?key|pairing[ _-]?code|secret|bearer_?token"
    r"|token|api[_-]?key|authorization|bearer"
)
# The [REDACTED]/token alternative must come first: the bare-token branch
# stops at "]", so without it a second pass would emit "[REDACTED]]".
_CRED_VALUE = (
    r"""(?P<val>\[REDACTED\]|\[(?:SSID|MAC|IPV6)_[0-9a-f]{8}\]"""
    r"""|'[^'\n]*'|"[^"\n]*"|(?i:Bearer\s+)[A-Za-z0-9._~+/-]{8,}={0,2}"""
    r"""|[^\s,;}\]]+)"""
)

# The optional quotes around the key are what let this match the JSON shape
# {"root_password": "abc"} as well as the YAML shape root_password: abc.
RE_CRED_KV = re.compile(
    rf"(?P<key>[\"']?\b(?:{_CRED_KEY})\b[\"']?)(?P<sep>\s*[:=]\s*){_CRED_VALUE}",
    re.IGNORECASE,
)

# NetworkManager's own shape: Config: added 'psk' value '<hidden>'
RE_CRED_NM = re.compile(
    rf"(?P<key>added\s+'(?:{_CRED_KEY})'\s+value\s+)(?P<val>'[^'\n]*')",
    re.IGNORECASE,
)

# Headers occasionally arrive in diagnostic messages without an
# ``Authorization:`` key. Match the standard token68-style value after a
# Bearer scheme, but require at least eight characters to avoid destroying
# prose such as "bearer token missing".
RE_BEARER_TOKEN = re.compile(
    r"(?P<key>\bbearer)(?P<sep>\s+)"
    r"(?P<val>[A-Za-z0-9._~+/-]{8,}={0,2})(?![A-Za-z0-9._~+/-=])",
    re.IGNORECASE,
)


def _sub_cred(m):
    val = m.group("val")
    if RE_ALREADY_DONE.match(val.strip("'\"")):
        return m.group(0)
    quote = val[0] if val[:1] in ("'", '"') else ""
    return f"{m.group('key')}{m.groupdict().get('sep', '')}{quote}{REDACTED}{quote}"


# --------------------------------------------------------------------------
# Rule 2 -- MAC addresses (own NIC, randomised scan MAC, and the BSSID).
# Runs BEFORE IPv6: a MAC also matches a loose IPv6 pattern.
# --------------------------------------------------------------------------
RE_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")


# --------------------------------------------------------------------------
# Rule 3 -- IPv6.
# Both forms require either "::" or a full 8 groups. A naive
# (?:[0-9a-f]{1,4}:){2,7} pattern matches the "01:42:05" in every timestamp
# in this file -- do not use one.
# --------------------------------------------------------------------------
RE_IPV6 = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"  # full form
    # Leading compression, including the two allowlisted values "::" and
    # "::1". This branch is needed because the general compressed branch
    # below requires at least one group before "::".
    r"|(?<![:\w])::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![:\w])"
    r"|(?<![:\w])(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![:\w])"
)
# Loopback and unspecified are not identifying.
IPV6_ALLOWLIST = {"::1", "::"}


# --------------------------------------------------------------------------
# Rule 4 -- SSID, anchored on context.
# An SSID is arbitrary user text, so it cannot be matched by shape. Each
# pattern below anchors on the surrounding message and captures group "val".
# Every value captured here is also LEARNED and swept globally in pass 2,
# which is what catches message shapes not enumerated here.
# --------------------------------------------------------------------------
RE_SSID = [
    re.compile(r"(?P<pre>Config: added 'ssid' value ')(?P<val>[^'\n]{1,32})(?P<post>')"),
    re.compile(r"(?P<pre>SSID=')(?P<val>[^'\n]{1,32})(?P<post>')"),
    re.compile(r"(?P<pre>associate with SSID ')(?P<val>[^'\n]{1,32})(?P<post>')"),
    re.compile(r"(?P<pre>wireless network \")(?P<val>[^\"\n]{1,32})(?P<post>\")"),
    re.compile(r"(?P<pre>\baccess point ')(?P<val>[^'\n]{1,32})(?P<post>')"),
    re.compile(r"(?P<pre>\bconnection ')(?P<val>[^'\n]{1,32})(?P<post>')"),
    re.compile(r"(?P<pre>policy: set ')(?P<val>[^'\n]{1,32})(?P<post>')"),
    re.compile(r"(?P<pre>\bssid\s*[:=]\s*[\"'])(?P<val>[^\"'\n]{1,32})(?P<post>[\"'])", re.I),
    # unquoted YAML/JSON form: ssid: HomeNet
    re.compile(
        r"(?P<pre>\bssid\s*[:=]\s*)" r"(?P<val>[^\s\"'#,;}\]][^\n#,;}\]]{0,31})(?P<post>)",
        re.I,
    ),
]

# Rules must be idempotent: several patterns overlap, and a value that has
# already been replaced must not be re-processed (doing so silently ate the
# surrounding quotes on SSID='...' lines).
RE_ALREADY_DONE = re.compile(r"^(?:\[(?:SSID|MAC|IPV6)_[0-9a-f]{8}\]|\[REDACTED\])$")

# Rule 5 -- the backend config dump embeds a YAML map whose *keys* are every
# network the machine has ever joined:
#     config DEBUG CONF:   wifi:
#     config DEBUG CONF:     KnownWifis:
#     config DEBUG CONF:       HomeNet:
# Empty ({}) in this sample, so no regex above would ever have caught it.
# Needs indentation tracking, not a line pattern.
RE_CONF_LINE = re.compile(r"^(?P<pre>.*?CONF:)(?P<yaml>.*)$")
RE_KNOWN_WIFIS = re.compile(r"^(?P<indent>\s*)KnownWifis:\s*(?P<inline>\S*)\s*$")
RE_YAML_KEY = re.compile(r"^(?P<indent>\s*)(?P<key>[^\s:#][^:\n]*?)(?P<rest>:.*)$")

# --------------------------------------------------------------------------
# Rule 7 -- IANA timezone. (R6 in the spec is the pass-2 literal sweep at the
# bottom of this file.) Order-independent -- nothing else matches
# "Area/Location" -- so it is applied last in pass 1.
#
# Unlike an SSID, a zone name has a shape: a closed area list and a location
# out of [A-Za-z_]. That makes this rule high-precision rather than a
# heuristic. systemd-timedated is the reason it has to live here at all -- it
# logs "Changed time zone to '<Area>/<City>' (CST)." and no source-level fix in
# the backend can ever reach a line systemd wrote.
#
# The deprecated single-token aliases (Japan, Turkey, Iran, ...) are out of
# scope: with no slash to anchor on, matching them means matching bare words.
# --------------------------------------------------------------------------
TZ_MASK = "*****"
RE_TIMEZONE = re.compile(
    r"\b(?P<area>Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia"
    r"|Brazil|Canada|Chile|Etc|Europe|Indian|Mexico|Pacific|US)"
    # The optional [+-]\d{1,2} tail is for Etc/GMT-6, which does reveal an
    # offset. Two-segment locations (America/Argentina/Buenos_Aires) too.
    r"/(?P<loc>[A-Za-z_]+(?:[+-]\d{1,2})?(?:/[A-Za-z_]+)?)\b"
)
# Zero-offset zones identify nobody, and "this machine never synced its clock"
# is exactly the signal needed to debug the timezone code itself. Etc/GMT-6 is
# NOT here on purpose -- it carries an offset.
TIMEZONE_ALLOWLIST = re.compile(r"^Etc/(?:UTC|GMT|Universal|Zulu|Greenwich)$")
# The trailing parenthetical is itself a location hint -- "(CST)" pins UTC-6 and
# timedatectl writes "(CEST, +0200)" outright -- but "(OOM)", "(NAND)", "(KPTI)"
# and "(IOAM)" also appear in kernel messages, so a bare \([A-Z]{3,5}\) rule is
# unusable and a numeric-offset rule is worse: [+-]\d{4} matches sensor readings
# hundreds of times per report. The anchor is what makes this safe -- only a
# parenthetical directly after a zone this rule just masked, so its whole
# contents can go. Also catches the abbreviation left behind when the value
# arrived already masked by the backend's own redact_timezone().
# Not a lookbehind: systemd quotes the zone, and Python needs fixed width.
RE_TZ_ABBREV = re.compile(rf"(?P<pre>/{re.escape(TZ_MASK)}['\"]?\s*)\([^)\n]{{0,32}}\)")


class RedactionCancelled(Exception):
    """Raised by ``redact()`` when its ``cancelled`` predicate fires mid-pass.

    Generic on purpose: this module is vendored standalone into both
    meticulous-watcher and meticulous-backend, so it cannot know about either
    consumer's own request-lifecycle exceptions. A consumer that wires up a
    ``cancelled`` predicate is expected to catch this and translate it into
    whatever its own callers already watch for.
    """


# "A few hundred iterations" per the design this implements: frequent enough
# that an aborted pass 1 stops within a fraction of a second of being
# signalled, rare enough that the check itself never shows up against a
# >100k-line pass. Pass 2 checks every iteration instead of on an interval --
# it is bounded by the SSID count, not the line count, so one iteration is
# already the right grain there.
_CANCEL_CHECK_INTERVAL = 500


def _check_cancelled(cancelled, index=0, interval=1):
    """Raise RedactionCancelled if ``cancelled`` is due to be polled and says
    to stop.

    A no-op unless ``cancelled`` is given, ``index`` lands on ``interval``,
    and calling it reports True. Broken out of redact() itself so both passes
    can each spend a single call on this rather than an inline compound
    condition, which otherwise pushes redact()'s own branching past this
    project's complexity ceiling for no behavioural reason.
    """
    if cancelled is not None and index % interval == 0 and cancelled():
        raise RedactionCancelled()


def redact(text, key, state=None, cancelled=None):
    """Two passes: anchored rules (which learn SSIDs), then a literal sweep.

    ``state`` carries KnownWifis block tracking across calls, for callers that
    feed one log record at a time. Omit it and every call starts fresh, which is
    what a whole-file caller wants.

    ``cancelled``, if given, is a zero-argument callable returning True once
    the caller's work should stop -- a ``threading.Event().is_set`` or
    equivalent. It is checked periodically in pass 1 and once per learned SSID
    in pass 2. Firing it raises ``RedactionCancelled`` and abandons the call
    outright: no partially redacted text is ever returned.
    """
    learned_ssids = set()
    if state is None:
        state = RedactionState()

    # ---------------- pass 1 ----------------
    out_lines = []

    for index, line in enumerate(text.splitlines(keepends=True)):
        _check_cancelled(cancelled, index, _CANCEL_CHECK_INTERVAL)

        line = RE_CRED_KV.sub(_sub_cred, line)
        line = RE_CRED_NM.sub(_sub_cred, line)
        line = RE_BEARER_TOKEN.sub(_sub_cred, line)

        line = RE_MAC.sub(
            lambda m: (
                m.group(0)
                if MAC_ALLOWLIST.match(m.group(0))
                else _pseudonym("MAC", m.group(0).lower(), key)
            ),
            line,
        )

        line = RE_IPV6.sub(
            lambda m: (
                m.group(0)
                if m.group(0) in IPV6_ALLOWLIST
                else _pseudonym("IPV6", m.group(0).lower(), key)
            ),
            line,
        )

        for pattern in RE_SSID:

            def _sub_ssid(m):
                val = m.group("val").strip("'\"")
                if not val or CONNECTION_ALLOWLIST.match(val) or RE_ALREADY_DONE.match(val):
                    return m.group(0)
                learned_ssids.add(val)
                token = _pseudonym("SSID", val, key)
                pre, post = m.group("pre"), m.groupdict().get("post", "")
                return f"{pre}{token}{post}"

            line = pattern.sub(_sub_ssid, line)

        line = RE_TIMEZONE.sub(
            lambda m: (
                m.group(0)
                if TIMEZONE_ALLOWLIST.match(m.group(0))
                else f"{m.group('area')}/{TZ_MASK}"
            ),
            line,
        )
        line = RE_TZ_ABBREV.sub(rf"\g<pre>({TZ_MASK})", line)

        # KnownWifis block: keys are SSIDs.
        if line.endswith("\r\n"):
            line_body, line_ending = line[:-2], "\r\n"
        elif line.endswith(("\n", "\r")):
            line_body, line_ending = line[:-1], line[-1]
        else:
            line_body, line_ending = line, ""

        conf = RE_CONF_LINE.match(line_body)
        if conf:
            yaml_part = conf.group("yaml")
            if state.known_wifis_indent is not None:
                km = RE_YAML_KEY.match(yaml_part)
                indent = len(km.group("indent")) if km else None
                if km and indent > state.known_wifis_indent:
                    # First deeper key fixes the SSID level. Anything deeper
                    # than that is a per-network attribute (password,
                    # last_used) -- not an SSID, and handled by rule 1.
                    # This must happen even for an already-redacted key, or a
                    # second pass over redacted output locks onto the
                    # attribute level and pseudonymises "password" as an SSID.
                    if state.ssid_key_indent is None:
                        state.ssid_key_indent = indent
                    val = km.group("key").strip()
                    if indent == state.ssid_key_indent and not RE_ALREADY_DONE.match(val):
                        learned_ssids.add(val)
                        line = (
                            conf.group("pre")
                            + km.group("indent")
                            + _pseudonym("SSID", val, key)
                            + km.group("rest")
                            + line_ending
                        )
                elif yaml_part.strip():
                    state.known_wifis_indent = None
                    state.ssid_key_indent = None
            kw = RE_KNOWN_WIFIS.match(yaml_part)
            if kw and kw.group("inline") in ("", "|", ">"):
                state.known_wifis_indent = len(kw.group("indent"))
                state.ssid_key_indent = None

        out_lines.append(line)

    text = "".join(out_lines)

    # ---------------- pass 2: literal sweep ----------------
    # Catches the SSID wherever it appears in a message shape pass 1 does not
    # know about. Longest-first so a substring SSID cannot shadow a longer one.
    for ssid in sorted(learned_ssids, key=len, reverse=True):
        _check_cancelled(cancelled)
        if len(ssid) < MIN_SWEEP_LEN or RE_ALREADY_DONE.match(ssid):
            continue
        text = re.sub(
            rf"(?<![\w-]){re.escape(ssid)}(?![\w-])",
            _pseudonym("SSID", ssid, key),
            text,
        )

    return text, learned_ssids


def _read_key(path):
    with open(path, "rb") as fh:
        key = fh.read()
    if len(key) != KEY_SIZE:
        raise ValueError(f"redaction key at {path!r} must be exactly {KEY_SIZE} bytes")
    return key


def load_key(path=DEFAULT_KEY_PATH):
    """Per-device key. Not a fleet secret: compromise of one device's key
    reveals nothing about any other device's reports."""

    import time

    try:
        key = _read_key(path)
        os.chmod(path, 0o600)
        return key
    except FileNotFoundError:
        pass

    key = os.urandom(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another request won the first-use race. Keep its key so tokens stay
        # stable across concurrent reports.
        # wait 0.1s to make sure the file is not being actively written and thus the key be incomplete
        time.sleep(0.1)
        key = _read_key(path)
        os.chmod(path, 0o600)
        return key

    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
        fh.flush()
        os.fsync(fh.fileno())
    return key


if __name__ == "__main__":
    import sys

    src = sys.argv[1]
    key = os.environ.get("REDACTION_KEY", "test-key-not-for-production").encode()
    with open(src, encoding="utf-8", errors="replace") as fh:
        out, ssids = redact(fh.read(), key)
    sys.stdout.write(out)
    print(f"[learned {len(ssids)} SSID(s)]", file=sys.stderr)
