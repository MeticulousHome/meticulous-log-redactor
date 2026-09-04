# Bug-Report Log Redaction Filter — Implementation Spec

| | |
|---|---|
| **Status** | Draft for implementation |
| **Applies to** | `machine_logs.txt` in the bug-report bundle produced by `meticulous-watcher` |
| **Reference implementation** | `redactor.py` (this directory) — the only copy, vendored by both services as a submodule; verified against a real 56,920-line bundle |
| **Scope** | The **must-redact** set only. See §1.2 for what is deliberately excluded. |
| **Sign-off needed from** | DPO (classification), Firmware (integration point) |

> **Do not paste real values into this document, the test fixtures, or the
> commit message.** Test vectors below are synthetic. Verification against a
> real bundle is by file+line reference only (§10.2). A spec that carries the
> live root password it exists to remove has defeated itself.

---

## 1. Scope

### 1.1 In scope — the must-redact set

Nine classes. The original seven were confirmed in production bundles; pairing
codes and bearer tokens are defense-in-depth coverage for the authorization
flows added later:

| Class | Example location in a real bundle | Why it must go |
|---|---|---|
| **Wi-Fi SSID** | `NetworkManager` / `wpa_supplicant` lines; `KnownWifis` map in the backend config dump | Home network name; frequently contains surnames or flat numbers |
| **BSSID** (access-point MAC) | `wpa_supplicant`: `Associated with <mac>` | Resolvable to street-level coordinates via public WPS/wardriving databases. **Highest-risk item in the bundle.** |
| **Device MAC** (wlan0, and randomised scan MAC) | `NetworkManager`: `set-hw-addr` | Permanent hardware identifier (GDPR Recital 30) |
| **IPv6 address** | `avahi-daemon` address records | Stable link-local identifier derived from a persistent secret |
| **`root_password`** | backend `config DEBUG CONF:` dump — **plaintext** | Credential. With `ssh_enabled: true` this is remote root on the unit. |
| **`APPassword`** | backend `config DEBUG CONF:` dump | Credential for the machine's own hotspot |
| **Pairing code** | diagnostic text keyed as `pairing code:` | Short-lived credential that authorizes a new client |
| **Bearer token** | HTTP/auth diagnostic text | Long-lived per-device API credential |
| **IANA timezone** | `systemd-timedated`: `Changed time zone to '<Area>/<City>' (CST).` | City-level location. The trailing parenthetical is part of the class — `(CST)` pins the offset on its own. |

The Wi-Fi PSK is *already* correctly redacted upstream by NetworkManager
(`Config: added 'psk' value '<hidden>'`). The `root_password` line is the
inconsistency this filter closes — see §12.2 for the proper fix.

The timezone class is the one where this filter is the **only** possible defence.
In the 56,920-line reference bundle there are 11 IANA-shaped occurrences: 6 are
`Etc/UTC` (allowlisted, see §1.2) and 5 carry a real city zone. Three of those
five were written by `systemd-timedated`, so no amount of fixing the backend's
own call sites can reach them. The other two now come out redacted at source as
well (§13).

### 1.2 Out of scope — and why

These were assessed and **deliberately left in**. Do not "helpfully" add them.

| Excluded | Reason |
|---|---|
| Serial (`332233`), hostname (`meticulous<Name>-<serial>`), hawkbit controller ID | Support needs them to correlate a report to a unit. They *are* personal data under Recital 30 because we can join them to a customer record — managed by retention policy and the Art. 30 record, not by this filter. |
| `APName` | The machine's own hotspot name, not the user's network. **Review closed:** `wifi.py` overwrites it on every init with `HostnameManager.generateDeviceName()` and nothing else writes it, so it is always machine-derived — the reference bundle carries `APName: Meticulous<MachineName>`. It is the same identifier as the hostname, which is excluded above and appears in the clear in kernel, avahi and NetworkManager lines. Redacting it would tokenise it in some lines and not others, for no gain. |
| Zero-offset timezones: `Etc/UTC`, `Etc/GMT`, `Etc/Universal`, `Etc/Zulu`, `Etc/Greenwich`, bare `UTC` | Identify nobody, and "this machine never synced its clock" is exactly the signal needed to debug the timezone code. `Etc/GMT-6` is **not** on this list — it carries an offset. |
| Numeric UTC offsets (`+0200`, `-0600`) | A `[+-]\d{4}` rule is unusable: the reference bundle matches it hundreds of times on ESP sensor readings (`-2404`, `-9815`). Offsets are only removed where they sit inside a parenthetical attached to a zone the filter just masked. |
| Bare timezone abbreviations (`CST`, `CEST`) not attached to a zone | Same collision problem: `(OOM)`, `(NAND)`, `(KPTI)` and `(IOAM)` all appear in kernel messages in the reference bundle. |
| Deprecated single-token zone aliases (`Japan`, `Turkey`, `Iran`, `Cuba`, …) | No `/` to anchor on, so matching them means matching bare common words. Not offered by the UI's timezone list. |
| NetworkManager connection UUID | Stable per-network identifier, weakly linking. Easy to add if the DPO wants it. |
| The machine's own DHCP address | RFC1918, and it is the *machine's own* lease. ~37k occurrences; redacting it destroys all `tornado.access` correlation for no privacy gain. |
| Behavioural stream (backlight dim/wake, encoder events, boot times) | Cannot be filtered without destroying the diagnostics the bundle exists for. This is a retention-limit and privacy-notice question, **not** a filter rule. Tracked separately. |

### 1.3 Files the filter must process

| File | Action |
|---|---|
| `machine_logs.txt` | **Must** run the filter |
| `machine_status.json` | No must-redact items (re-verified for the timezone class: none present). Contains hostname only. |
| `report_info.json` | No must-redact items (re-verified for the timezone class: none present). Contains `machineID`, ticket, local UUID. |
| `debug/**/*.json.zst` | **Carries `.config.time_zone`** — a must-redact value under §1.1, in a file this filter does not process. See §12.4. No credentials: `shot_debug_manager` copies only the `user` config section and blanks `wifi` explicitly. Also carries `.config.hostname_override` (user-typed) and a `.logs` array, which as of §13 arrives already redacted. Otherwise as before: stock profile names, stock author, no SSID/MAC. **Re-check if user-authored profiles or a cloud account ID ever land in the `author` field.** |

---

## 2. Invariants

Testable properties. CI must assert all seven.

1. **I1 — Completeness.** After filtering, no in-scope value appears anywhere in the output.
2. **I2 — Line preservation.** Output line count equals input line count. Redaction never splits, joins, or drops lines.
3. **I3 — Idempotency.** `f(f(x)) == f(x)`. Re-processing already-filtered content is a no-op. (Bundles get re-processed; without this you get `[REDACTED]]`.)
4. **I4 — Structural validity.** Embedded YAML/JSON stays parseable — quoting style around a replaced value is preserved.
5. **I5 — Diagnostic preservation.** No false positives on the values listed in §9.2.
6. **I6 — Fail closed.** If the filter raises, the bundle is **not** uploaded. Never fall back to shipping the unfiltered file. *(Read-time layer only. The emit-time layer in the backend cannot abort a caller's `logger.info()`, so it fails to a content-free placeholder instead — see §13.2.)*
7. **I7 — Cross-service agreement.** A given value produces the same replacement in `meticulous-watcher` and `meticulous-backend`. Held structurally — both vendor this repository as a submodule at `log_redactor/` — and asserted by `tests/test_redaction_contract.py`, which each consumer runs against the commit it has pinned (§13).

---

## 3. Output vocabulary

Three replacement forms, and the distinctions are deliberate.

```
[REDACTED]              credentials — unconditional, irreversible, no correlation
[SSID_a1b2c3d4]         identifiers — per-device pseudonym
[MAC_a1b2c3d4]
[IPV6_a1b2c3d4]
America/*****           timezone — coarsened, not pseudonymised
America/***** (*****)   ...including any parenthetical attached to it
```

**Token grammar:** `[` `KIND` `_` 8 lowercase hex `]` where `KIND ∈ {SSID, MAC, IPV6}`.

**The timezone keeps its area.** A continent identifies nobody, and it preserves
enough to tell a DST bug from a clock-never-synced one. This is the one place
partial masking is acceptable: what survives is a coarser value, not a fragment
of a unique identifier the way an SSID prefix would be. The output deliberately
matches the backend's `TimezoneManager.redact_timezone()` byte for byte, so the
two layers agree on the same value — pseudonymising to `[TZ_a1b2c3d4]` was
considered and rejected for that reason.

**The separator is an underscore, not a colon — this is load-bearing, not
cosmetic.** `[SSID:a1b2c3d4]` is itself a `key:value` shape, and rule R4i
matches inside it, learning the hash as if it were a network name. See §8.3.

**Credentials are never pseudonymised.** Correlating passwords across reports
has no diagnostic value, and a stable hash of a password is a cracking oracle.

---

## 4. Key management

```
pseudonym(kind, value) = "[" + kind + "_" + HMAC-SHA256(K_device, kind || 0x00 || value)[0:4].hex() + "]"
```

- `K_device`: 32 random bytes, generated on first use, stored at
  `/root/.redaction_key`, mode `0600`. Both `meticulous-watcher` and
  `meticulous-backend` run as `User=root` and read this same path — that is what
  makes a token for one network identical in both services (§13). Whichever
  service starts first creates it; `load_key` handles the race with `O_EXCL`.
- **Per-device, not fleet-wide.** Same value → same token *within* one unit's
  reports, so an engineer can still see "the MAC changed at this boot" or
  "same AP as the previous report" — the actual diagnostic need. Across units
  the tokens are unlinkable, so a compromised key exposes nothing about any
  other device.
- A fleet-wide key baked into firmware would be strictly worse: extractable
  once, then every report in the fleet becomes cross-linkable.
- The key must **not** be included in the bundle.
- Rotating the key breaks correlation with historical reports. Do not rotate
  on update.

---

## 5. Rules

### R1 — Credentials

Two patterns. Runs **first** (see §6).

```
KEY   := root_?password|ap_?password|passwd|password|passphrase
       |psk|pre_?shared_?key|pairing[ _-]?code|secret|bearer_?token
       |token|api[_-]?key|authorization|bearer

VALUE := \[REDACTED\]                          ← must be first alternative
       | \[(?:SSID|MAC|IPV6)_[0-9a-f]{8}\]     ← must be second
       | '[^'\n]*'
       | "[^"\n]*"
       | (?i:Bearer\s+)[A-Za-z0-9._~+/-]{8,}={0,2}
       | [^\s,;}\]]+

R1a (key/value, YAML + JSON):
    (?P<key>["']?\b(?:KEY)\b["']?)(?P<sep>\s*[:=]\s*)(?P<val>VALUE)     [IGNORECASE]

R1b (NetworkManager form):
    (?P<key>added\s+'(?:KEY)'\s+value\s+)(?P<val>'[^'\n]*')             [IGNORECASE]

R1c (standalone Bearer scheme):
    (?P<key>\bbearer)(?P<sep>\s+)(?P<val>[A-Za-z0-9._~+/-]{8,}={0,2}) [IGNORECASE]
```

**Replacement:** `key` + `sep` + `[REDACTED]`, re-wrapped in the original quote
character if the matched value was quoted (satisfies I4).

**Guard:** if the matched value is already `[REDACTED]` or a pseudonym token,
return the match unchanged (I3).

**Notes:**
- The optional quotes around `key` are what make `{"root_password": "abc"}`
  match as well as `root_password: abc`. Without them the closing quote breaks
  key↔separator adjacency and the JSON form silently passes through. See §8.1.
- The key must sit **immediately** against the separator. This is what stops
  the rule eating `Password already set: True` and `password changed for root`.
- The `[REDACTED]` alternative must precede the bare-token branch, which stops
  at `]` and would otherwise emit `[REDACTED]]` on a second pass.
- The Bearer-aware value alternative consumes both the scheme and token after
  an `Authorization:` key. R1c covers the same token shape when a diagnostic
  message contains the scheme without the header key; its minimum length avoids
  treating ordinary prose such as `bearer token missing` as a credential.

### R2 — MAC / BSSID

```
\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b
```

**Replacement:** `[MAC_…]`, normalising the value to lowercase before hashing
so `C0:EE:…` and `c0:ee:…` produce the same token.

**Allowlist** (identify no one, keep for diagnostics):
`ff:ff:ff:ff:ff:ff`, `00:00:00:00:00:00`, `33:33:*` (IPv6 multicast),
`01:00:5e:*` (IPv4 multicast).

### R3 — IPv6

```
\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b                      ← full 8-group form
|
(?<![:\w])(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![:\w])
                                                                   ← compressed (::) form
```

**Replacement:** `[IPV6_…]`, lowercased before hashing.
**Allowlist:** `::1`, `::`.

**Critical:** every branch requires either `::` or a full 8 groups. A loose
`(?:[0-9a-f]{1,4}:){2,7}` matches the `01:42:05` in **every timestamp in the
file**. See §8.2.

### R4 — SSID, context-anchored

An SSID is arbitrary user text and cannot be matched by shape. Nine patterns,
each anchoring on surrounding message text and capturing `pre` / `val` / `post`:

```
R4a  (?P<pre>Config: added 'ssid' value ')(?P<val>[^'\n]{1,32})(?P<post>')
R4b  (?P<pre>SSID=')(?P<val>[^'\n]{1,32})(?P<post>')
R4c  (?P<pre>associate with SSID ')(?P<val>[^'\n]{1,32})(?P<post>')
R4d  (?P<pre>wireless network ")(?P<val>[^"\n]{1,32})(?P<post>")
R4e  (?P<pre>\baccess point ')(?P<val>[^'\n]{1,32})(?P<post>')
R4f  (?P<pre>\bconnection ')(?P<val>[^'\n]{1,32})(?P<post>')
R4g  (?P<pre>policy: set ')(?P<val>[^'\n]{1,32})(?P<post>')
R4h  (?P<pre>\bssid\s*[:=]\s*["'])(?P<val>[^"'\n]{1,32})(?P<post>["'])        [IGNORECASE]
R4i  (?P<pre>\bssid\s*[:=]\s*)(?P<val>[^\s"'#,;}\]][^\n#,;}\]]{0,31})(?P<post>)  [IGNORECASE]
```

**Replacement:** `pre` + `[SSID_…]` + `post`.

**Every captured value is added to the `learned` set** — this is what feeds R6.

**Guards:** skip if the value is empty, matches `CONNECTION_ALLOWLIST`, or is
already a pseudonym token.

**`CONNECTION_ALLOWLIST`** — R4f is broad because NetworkManager uses identical
wording for non-Wi-Fi connections: `^(?:lo|usb\d+|eth\d+|Wired connection \d+)$`
(case-insensitive). Anything *not* on this list is still redacted:
over-redaction is the safe direction for a field holding arbitrary user text.

### R5 — `KnownWifis` block

The backend config dump embeds a YAML map whose **keys** are every network the
machine has ever joined:

```
config DEBUG CONF:   wifi:
config DEBUG CONF:     KnownWifis:
config DEBUG CONF:       HomeNet:            ← SSID (redact)
config DEBUG CONF:         password: ...     ← attribute (R1 handles)
config DEBUG CONF:         last_used: ...    ← attribute (leave)
```

This needs indentation tracking, not a line pattern. **No regex in R4 would
ever catch it**, and it is empty (`{}`) on a freshly-provisioned unit — so it
is invisible in most test bundles while holding a full location history on a
real one.

```
CONF_LINE  := ^(?P<pre>.*?CONF:)(?P<yaml>.*)$
KNOWN      := ^(?P<indent>\s*)KnownWifis:\s*(?P<inline>\S*)\s*$
YAML_KEY   := ^(?P<indent>\s*)(?P<key>[^\s:#][^:\n]*?)(?P<rest>:.*)$
```

**Algorithm:**
1. On a `KnownWifis:` line with empty/`|`/`>` inline value, record its indent
   as `block_indent` and reset `ssid_indent`.
2. While `block_indent` is set, for each `CONF:` line matching `YAML_KEY`:
   - If `indent > block_indent`: if `ssid_indent` is unset, set it to this
     indent. Then if `indent == ssid_indent` **and** the key is not already a
     token, redact the key and learn it.
   - Else if the line is non-blank: clear `block_indent` and `ssid_indent`.

**Step 2's `ssid_indent` assignment must happen even for an already-redacted
key**, or a second pass locks onto the attribute level and pseudonymises
`password` as an SSID. See §8.4.

### R6 — Literal sweep (pass 2)

For each learned SSID, longest-first, replace every remaining occurrence in the
whole document:

```
(?<![\w-])<escaped literal>(?![\w-])   →   [SSID_…]
```

**Rationale.** R4's anchors cannot enumerate every message that mentions a
network name. R6 converts an open-ended problem into a closed one: whatever R4
*learns* gets removed everywhere, including message shapes we have never seen.
In testing this is what catches free-text lines such as
`user renamed network to <ssid> today`.

**Skip** values shorter than `MIN_SWEEP_LEN = 4` (collision risk against
ordinary log text — an SSID of `up` would shred the file) and values that are
already tokens. Longest-first prevents a short SSID shadowing a longer one that
contains it.

**Accepted limitation:** SSIDs under 4 characters get anchored coverage only.

### R7 — IANA timezone

Two substitutions, in this order, both line-local:

```
\b(?P<area>Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Brazil
   |Canada|Chile|Etc|Europe|Indian|Mexico|Pacific|US)
/(?P<loc>[A-Za-z_]+(?:[+-]\d{1,2})?(?:/[A-Za-z_]+)?)\b   →   <area>/*****

(?P<pre>/\*\*\*\*\*['"]?\s*)\([^)\n]{0,32}\)             →   <pre>(*****)
```

**Skip** anything matching `^Etc/(?:UTC|GMT|Universal|Zulu|Greenwich)$` (§1.2).

**Rationale.** Unlike an SSID, a zone name *has* a shape — a closed area list and
a location out of `[A-Za-z_]` — so this is a precise rule rather than a
heuristic. The optional `[+-]\d{1,2}` tail exists for `Etc/GMT-6`, which does
carry an offset and is therefore not allowlisted. The optional second segment
handles `America/Argentina/Buenos_Aires`.

**The second substitution is the whole point of the first one.** Masking
`America/Mexico_City` while leaving `(CST)` beside it accomplishes nothing. It is
anchored on a mask this rule just wrote — not a free-standing
`\([A-Z]{3,5}\)` — because kernel messages are full of `(OOM)`, `(NAND)`,
`(KPTI)` and `(IOAM)`. Being anchored is also what makes it safe to take the
whole parenthetical, which is needed for `timedatectl`'s `(CEST, +0200)` form.

It is *not* a lookbehind: systemd quotes the zone (`'America/*****' (CST)`), so
the mask and the parenthetical are separated by a quote, and Python requires
fixed-width lookbehind.

**Order-independent** — no other rule matches `Area/Location`, and no rule
matches this rule's output. Applied last in pass 1 for definiteness.

---

## 6. Execution order

Order is **load-bearing**. Implement as an ordered pipeline, not a rule set.

| Step | Rule | Ordering constraint |
|---|---|---|
| 1 | R1 credentials | **Before R2/R4.** A password that happens to look like a MAC must be destroyed outright, not pseudonymised into a reversible-by-correlation token. |
| 2 | R2 MAC | **Before R3.** A MAC matches a loose IPv6 pattern; R2 is the more specific rule and must consume it first. |
| 3 | R3 IPv6 | — |
| 4 | R4 SSID (a→i in order) | R4h before R4i, so the quoted form wins and quotes survive. |
| 5 | R5 KnownWifis | After R4 on the same line. |
| 6 | R7 timezone | Order-independent; last in pass 1 so the abbreviation anchor sees a mask this pass wrote. |
| — | *end of pass 1* | R1–R5 and R7 are line-local; R6 needs the complete learned set. |
| 7 | R6 literal sweep | Whole document, after pass 1 completes. |

---

## 7. Tunables

| Constant | Value | Effect of changing |
|---|---|---|
| `MIN_SWEEP_LEN` | `4` | Lower → more thorough sweep, rising risk of shredding ordinary log text |
| `MAC_ALLOWLIST` | broadcast, null, multicast | Additions reduce redaction |
| `IPV6_ALLOWLIST` | `::1`, `::` | as above |
| `CONNECTION_ALLOWLIST` | `lo`, `usbN`, `ethN`, `Wired connection N` | Additions reduce redaction — **each addition needs review** |
| pseudonym length | 8 hex (32 bits) | Collision probability negligible at bundle scale |

---

## 8. Implementation hazards

Every one of these was a real defect caught by testing, not a hypothetical.
An independent implementation will hit them again.

### 8.1 Quoted keys break key↔separator adjacency
`{"root_password": "abc"}` — the closing `"` sits between key and `:`, so
`\bpassword\b\s*[:=]` does not match and **the credential ships**. The key
pattern must tolerate wrapping quotes.

### 8.2 A loose IPv6 pattern eats every timestamp
Log timestamps are `HH:MM:SS`; digits are valid hex. `(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}`
matches `01:42:05`. Require `::` or a full 8 groups.

### 8.3 A `[KIND:hash]` token is itself a `key:value` shape
With a colon separator, R4i matches *inside the filter's own output* and learns
the hash as a network name, producing nested `[SSID:[SSID:…]]`. Use `_`.

### 8.4 Stateful block handlers must stay correct on already-redacted input
The R5 indent level must be fixed from the first deeper key **whether or not**
that key is already redacted; otherwise pass 2 latches onto the attribute level
and pseudonymises `password` as an SSID. This only shows up in an idempotency
test — which is why I3 is mandatory.

### 8.5 Overlapping rules must be idempotent individually
R4b and R4h both match `SSID='…'`. Without an already-done guard the second
application strips the surrounding quotes, breaking I4.

### 8.6 Portability
R3 and R6 use lookbehind. Rust's `regex` crate does not support it — a port to
`crash-reporter` (Rust) needs `fancy-regex` or restructured patterns with
explicit boundary capture. Python `re` and PCRE are fine as written.

---

## 9. Test vectors

### 9.1 Must be redacted (synthetic)

| Input fragment | Expected output |
|---|---|
| `Config: added 'ssid' value 'HomeNet'` | `Config: added 'ssid' value '[SSID_…]'` |
| `wlan0: Trying to associate with SSID 'HomeNet'` | `…SSID '[SSID_…]'` |
| `Connected to wireless network "HomeNet"` | `…"[SSID_…]"` |
| `SME: Trying to authenticate with aa:bb:cc:dd:ee:ff (SSID='HomeNet' freq=2437 MHz)` | `…with [MAC_…] (SSID='[SSID_…]' freq=2437 MHz)` |
| `policy: set 'HomeNet' (wlan0) as default` | `policy: set '[SSID_…]' (wlan0) as default` |
| `set-hw-addr: set MAC address to AA:BB:CC:DD:EE:FF (scanning)` | `…to [MAC_…] (scanning)` |
| `Registering new address record for fe80::1122:3344:5566:7788 on wlan0.*.` | `…for [IPV6_…] on wlan0.*.` |
| `CONF:   root_password: s3cr3tvalue` | `CONF:   root_password: [REDACTED]` |
| `CONF:   APPassword: '123456789012'` | `CONF:   APPassword: '[REDACTED]'` |
| `pairing code: 482913` | `pairing code: [REDACTED]` |
| `Authorization: Bearer abcDEF-123_xyz987` | `Authorization: [REDACTED]` |
| `{"root_password": "abc123", "serial": "332233"}` | `{"root_password": "[REDACTED]", "serial": "332233"}` |
| `CONF:     KnownWifis:` → `CONF:       Some Network 5G:` | key → `[SSID_…]:` |
| `user renamed network to HomeNet today` *(R6 only)* | `user renamed network to [SSID_…] today` |
| `Changed time zone to 'America/Mexico_City' (CST).` | `Changed time zone to 'America/*****' (*****).` |
| `new system time zone: Europe/Berlin` | `new system time zone: Europe/*****` |
| `Time zone: America/Argentina/Buenos_Aires (ART, -0300)` | `Time zone: America/***** (*****)` |
| `Etc/GMT-6 carries an offset` | `Etc/***** carries an offset` |

### 9.2 Must **not** be altered

| Input fragment | Hazard it guards |
|---|---|
| `Firmware: BCM4339/2 … version 6.37.39.141 (73212ff CY)` | IPv4-lookalike version string |
| `tornado.access INFO 304 GET /api/v1/settings/ (10.10.0.79) 4.10ms` | machine's own lease, ~37k lines |
| `Serial_number: 332233 Batch_number: 0009` | out-of-scope identifier |
| `Config: added 'key_mgmt' value 'WPA-PSK WPA-PSK-SHA256 FT-PSK'` | key named `key_mgmt`, value contains `PSK` |
| `ssh_manager INFO … Password already set: True` | key not adjacent to separator |
| `pam_unix(chpasswd:chauthtok): password changed for root` | no separator |
| `Listening on gpg-agent.socket - … passphrase cache.` | no separator |
| `device (lo): Activation: starting connection 'lo'` | `CONNECTION_ALLOWLIST` |
| `Joining mDNS multicast group on interface lo.IPv6 with address ::1.` | `IPV6_ALLOWLIST` |
| any `2026-07-28 01:42:05.388326+00:00` | §8.2 timestamp collision |
| `Changed time zone to 'Etc/UTC' (UTC).` | timezone allowlist (§1.2) |
| `CONF:   time_zone: Etc/UTC` | timezone allowlist (§1.2) |
| `kernel: Out of memory (OOM) killer invoked` | R7's abbreviation anchor — must not fire without a zone |
| `kernel: page allocation failure (NAND) on mmcblk0` | as above |
| `kernel: enabled Kernel Page Table Isolation (KPTI)` | as above |
| `ESP sensor bundle: -2404 -9815 -9252 -8911` | why there is no numeric-offset rule (§1.2) |

### 9.3 Property tests

- **I3:** `f(f(x)) == f(x)` byte-for-byte, on both a real bundle and the §9.1 fixture.
- **I2:** line count preserved.
- **I4:** every `CONF:` YAML block and every embedded JSON object still parses.

---

## 10. Acceptance criteria

### 10.1 CI gate

The build fails unless all of:

1. Every §9.1 vector redacts as specified.
2. Every §9.2 vector is byte-identical to input.
3. I1–I7 hold.
4. Runtime under 5 s and peak RSS under 128 MB for a 10 MB log.
   *(Reference implementation: 1.7 s / 44 MB on 8.9 MB.)*

### 10.2 Pre-release check against a real bundle

Run the filter over an unfiltered production bundle and assert zero occurrences
of each in-scope value. Source the expected values **from the bundle at run
time** — read them out of the known line offsets, never hard-code them into the
test file.

Reference bundle for this spec: ticket 82, machine `332233`. In-scope values
occur at exactly these 25 lines of `machine_logs.txt`, and the filter must
change these and no others:

```
5932                                     device MAC (randomised, scanning)
6045 6046 6052 6056 6057 6063 6079 6087  SSID
6050                                     device MAC (real, restored)
6062                                     psk (already '<hidden>' upstream)
6074 6076 6077                           BSSID
6083 6085                                IPv6 link-local
6213 28636                               root_password
6271 28694                               APPassword
6628 29027 54188                         timezone (systemd-timedated, + abbreviation)
6629 29029                               timezone (backend timezone_manager)
```

Note what is **absent** from that list: the SSH key fingerprints (lines 897,
53655, 53728) and the hostname assignment (line 5540) are out of scope per
§1.2 and must survive untouched. So are the **6** `Etc/UTC` occurrences — a run
that changes 26 lines has over-redacted, and the most likely cause is the
timezone allowlist. A run that changes fewer than 25 has a rule that stopped
firing.

Verified end to end on this bundle: 25 changed lines, 56,920 in and 56,920 out,
`f(f(x)) == f(x)`, and no in-scope value present in the output.

---

## 11. Residual risk

| Risk | Severity | Status |
|---|---|---|
| SSID < 4 chars gets anchored coverage only | Low | Accepted (§R6) |
| An SSID appearing *only* in an unanticipated message shape is never learned, so R6 never fires on it | Medium | Mitigated by R4's breadth; re-audit on any NetworkManager/wpa_supplicant major version bump |
| A new backend log line prints a credential under an unlisted key name | Medium | Mitigated by R1's generic key list; **fix at source** (§12.2) |
| Behavioural/occupancy inference from timestamps | Medium | **Out of scope** — retention policy, tracked separately |
| Serial/hostname remain, linking the bundle to a customer record | By design | Art. 30 record + retention |
| Reproducing a DST or local-time bug now needs the customer to state their zone | Low | Accepted — the area survives, which distinguishes a DST bug from a never-synced clock |
| Every log line carries local wall-clock time, so comparing a report against the ticket's UTC creation time recovers the UTC offset | Medium | **Beyond the reach of a text filter.** Masking the zone name does not hide the offset. Belongs with the behavioural-timestamp item above, not in a rule. |
| `.config.time_zone` in `debug/**/*.json.zst` is a must-redact value in a file this filter does not process | Medium | **Open — §12.4** |

---

## 12. Integration

### 12.1 Where it runs

In `meticulous-watcher`, at bundle-assembly time, between log collection and
archive creation — so the unredacted text never reaches the archive, the upload
queue, or the support tooling. Per I6, a filter exception aborts the upload.

Wired in at `log_collector.format_logs_as_text`, which loads the key and redacts
before returning text to either the request handler or the archive builder. Both
call sites therefore fail closed: `archive_collector` keeps the redaction call
outside the collection exception handler on purpose, so a redaction failure
aborts archive creation rather than falling back to an archive of unsafe logs.

### 12.2 Fix the root cause too

This filter is a safety net, not the fix. `root_password` should never reach a
`config DEBUG CONF:` dump in the first place — mask it in the backend's config
serialiser, the way NetworkManager already masks `psk`. A downstream regex is
the wrong layer at which to protect a credential, and it only protects the one
path that happens to run through it.

### 12.3 Rollout

1. Land the filter with CI gates (§10.1) — no behaviour change to bundles yet.
2. Run in shadow mode on internal units; diff filtered vs unfiltered and review
   every changed line for over-redaction.
3. Enable by default.
4. Fix the serialiser (§12.2) independently.
5. Re-audit when NetworkManager, wpa_supplicant, or the config schema changes.

### 12.4 Open: the timezone in the shot debug files

Adding the timezone class (§1.1) opened a gap this filter cannot close. Every
`debug/**/*.json.zst` in the bundle carries `.config.time_zone`, because
`shot_debug_manager` deep-copies the whole `user` config section when it opens a
shot. The reference bundle has `Etc/UTC` there, which is allowlisted, so nothing
leaks today — but a machine configured with a real city zone puts it in every
shot debug file, and this filter only processes `machine_logs.txt`.

Two ways to close it, and the choice is a product decision because it trades
against shot diagnostics:

1. **Coarsen at source** — one line in `shot_debug_manager`, setting
   `time_zone` to `TimezoneManager.redact_timezone(...)` when the debug config is
   built. Consistent with everything else, but shot timing analysis loses the
   exact zone.
2. **Run the filter over the debug JSON too** — broader change, and the filter is
   currently specified for line-oriented log text, not JSON documents.

Also present in those files: `.config.hostname_override`, which is user-typed
free text and is *not* covered by any current rule (see §13, "not mirrored").
The embedded `.logs` array is already covered as of §13.

---

## 13. Second layer: emit-time redaction in the backend

The filter above runs at **read** time — the journal is redacted when a bundle is
built. That leaves the plaintext on the device until then: in the journal on
disk, in the shot-debug log files that ship inside the bundle, and in the Sentry
events that `LoggingIntegration` builds from `logger.error()` calls.

`meticulous-backend` therefore drives these same rules from a `logging.Filter`
(`log_redaction_filter.py`, which lives in the backend) that redacts each record
before any handler sees it. Same rules, same `/root/.redaction_key`, same tokens.

**The two services agreeing is a hard requirement**, not hygiene: if they
diverge, one network gets two different tokens inside a single report and the
report contradicts itself.

That is held structurally. Both services vendor this repository as a git
submodule checked out at `log_redactor/`, so there is one copy of the rules, not
two. It was briefly done by copying the file into each repo instead, and the two
copies diverged within a day — the backend runs `black` at line length 96 and the
watcher runs no formatter at all, so the same file could not be clean in both.
The contract test did not catch it, because formatting does not change a token.
Hence: **one copy, formatting owned by this repository, consumers exclude
`log_redactor/` from their own formatters.**

`tests/test_redaction_contract.py` pins the exact token strings for a fixed key
and runs in all three repositories — in each consumer against the submodule
commit it has pinned — so a bad bump fails that consumer's own test run.

Two pins can still be *valid but different*. No test can see that, since each
repository only knows its own. `meticulous-machine/scripts/check-redactor-pins.sh`
compares them after `update-sources.sh`: differing commits warn, and the watcher
being **behind** the backend fails the image build. Only that direction is unsafe
— the watcher filters last, immediately before the archive is written, so
anything the backend misses is still caught, but not the reverse.

Do not add service-specific rules here.

### 13.1 What the second layer adds

- **Placement.** Installed on every logger built by `MeticulousLogger.getLogger`,
  and on the root logger's handlers for third-party loggers that bypass it.
  `Logger.handle()` runs logger filters *before* `callHandlers()`, and
  sentry-sdk patches `callHandlers`, so this placement reaches the journal, every
  handler, and Sentry's `logentry.message` — deterministically, in that order.
- **A config-seeded sweep.** The rules match on shape, and no shape rule can
  catch a bare network name in an arbitrary message. At emit time there is no
  surrounding anchored line for R6 to have learned from either. The backend does
  not have to guess: it seeds the sweep with the actual `KnownWifis` keys and
  credentials from `MeticulousConfig`. Every value class it seeds is one this
  filter already redacts, and it emits the identical token, so the two layers can
  never disagree about the same string.
- **`RedactionState`.** The config dump arrives as one log record per line, so
  the KnownWifis block tracking in §R5 has to persist across calls. Learned SSIDs
  deliberately do **not** persist: on an always-on filter, a network named "Home"
  would tokenise that word in every later log line for the life of the process.

### 13.2 Fail mode differs, necessarily

I6 does not transfer. An exception raised inside a `logging.Filter` propagates
into whatever called `logger.info()`, so the emit-time layer cannot abort
anything. It replaces the message instead:

```
<redaction failed for a 'wifi' record: OSError>
```

and clears `exc_info`/`exc_text`/`stack_info` on that path. The logger name and
the exception type survive; no content does. It never logs from inside the
filter, which would recurse.

One subtlety worth keeping: a failure to read the config-seeded values must keep
failing loudly. An earlier revision extended the refresh deadline before calling
the provider, so a broken provider produced one placeholder and then two seconds
of records redacted by the shape rules alone — a bare network name in the clear
with nothing in the log to say so. There is a regression test for it.

### 13.3 What is *not* mirrored, and must not be removed

The backend's source-level redaction is not made redundant by any of this. These
cover classes no regex reaches, and they stay:

| Mechanism | Why the filter cannot replace it |
|---|---|
| `reportable_config.get_reportable_config` | An allowlist. It protects config keys nobody has added yet; a blocklist regex cannot. |
| `base_handler.redact_ip` | There is **no IPv4 rule** — see §1.2. |
| `TimezoneManager._redact_timezone_in` | Keeps the zone out of command output and exception text at source; the rule here is the backstop. |
| `ble_gatt`'s dropped DBus paths | `R2` needs colons; DBus writes `dev_C0_EE_40_…` with underscores. |
| `profiles._get_payload_md5` | No rule for `author` / `author_id`. |
| `{type(e).__name__}` instead of `{e}` | `R1` needs a `:` or `=` separator, so `nmcli … password X` is not matched. Do not restore `{e}`. |
| `sentry_privacy.sanitize_sentry_event` | A different egress path — structured event fields, not log text. |

`wifi.redact_ssid` is the exception: it now returns the same token this filter
produces instead of keeping the first two characters. It stays as a call-site
helper because a *scan result* is a neighbour's network name — not in our config,
so there is nothing to seed a sweep with and no anchored phrasing to learn from.

Still uncovered by either layer: the BLE hex dumps in `ble_gatt`
(`read_request` / `write_request` / `_update_data_loop`), which encode SSID,
password and local IPv4 as hex. No text rule can reach those; they need a
source-level fix.
