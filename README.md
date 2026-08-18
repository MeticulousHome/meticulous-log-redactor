# meticulous-log-redactor

Shared redaction rules for personal data in Meticulous machine logs. Stdlib only.

`REDACTION_SPEC.md` is the specification: what is redacted, what is deliberately
kept, and the evidence behind each decision. Read it before changing a rule.

## Who uses this

Both consumers vendor this repository as a git submodule checked out at
`log_redactor/`, so the import is `from log_redactor import redact` in either.

| consumer | when it runs | what it protects |
|---|---|---|
| `meticulous-watcher` | read time — `log_collector.format_logs_as_text`, once per bug report | the archive that leaves the device, including logs from NetworkManager, wpa_supplicant, avahi and RAUC that the backend never authored |
| `meticulous-backend` | emit time — `log_redaction_filter.LogRedactionFilter`, once per log record | the journal on disk, the shot-debug files inside the report, and Sentry's `logentry.message` |

They share `/root/.redaction_key`, so the same value produces the same token in
both. Keeping that true is the reason this is one module and not two files.

## Public API

Import from the package, not from `redactor` directly:

```python
from log_redactor import redact, pseudonym, load_key, RedactionState
```

- `redact(text, key, state=None, cancelled=None)` → `(redacted_text, learned_ssids)`.
  Two passes: anchored rules that learn SSIDs, then a literal sweep of what was
  learned. Pass a `RedactionState` when feeding one log record at a time, so
  the `KnownWifis` YAML block is still recognised across calls. Pass
  `cancelled`, a zero-argument callable returning True once the caller's work
  should stop, to make a whole-file call abandon cleanly instead of running to
  completion -- it raises `RedactionCancelled` and returns nothing.
- `pseudonym(kind, value, key)` → `[KIND_xxxxxxxx]`, for call sites that already
  know the value and want the token this module would have produced for it.
- `load_key(path=DEFAULT_KEY_PATH)` → the 32-byte per-device key, created on
  first use with mode `0600`. Not a fleet secret: one device's key reveals
  nothing about another device's reports.

`redact` is idempotent — `f(f(x)) == f(x)` — and the tests pin that.

## Development

**Clone it as `log_redactor`, not as the repository name:**

```
git clone https://github.com/MeticulousHome/meticulous-log-redactor log_redactor
cd log_redactor
uv sync --group dev
uv run pytest -v
uv run flake8 . && uv run black --check .
```

The repository root *is* the package, so the directory name is the import name.
pytest derives the package name from the containing directory
(`_pytest.python.Package.setup`), and a checkout left as `meticulous-log-redactor`
fails every test with a confusing `ImportError` about a module named `__init__`.
The submodule path in both consumers and the `path:` in this repository's own
workflow both pin the name, so this only bites a manual clone.

Formatting is owned here (black, line length 96, matching `meticulous-backend`).
Consumers exclude `log_redactor/` from their own formatters; do not reformat this
file from inside a consumer repository.

`tests/test_redaction_contract.py` pins exact token strings for a fixed key. It
runs here and in both consumers, against whatever commit they have checked out.
If it fails, a rule or the pseudonym framing changed — **do not** update the
expected values to make it pass.

## Changing a rule

A rule change is a three-repo sequence, in this order:

1. Land it here, with the spec section and the test vectors updated together.
2. Bump the submodule in `meticulous-watcher` first.
3. Bump the submodule in `meticulous-backend`.

That order matters. The watcher filters last, immediately before the archive is
written, so it must never be missing a rule the backend already has.
`meticulous-machine/scripts/check-redactor-pins.sh` fails the image build if the
two ever end up the other way round.
