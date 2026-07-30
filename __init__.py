"""Shared log redaction rules for the Meticulous espresso machine.

This package is consumed as a git submodule checked out at ``log_redactor/`` in
both meticulous-watcher and meticulous-backend, so ``from log_redactor import
redact`` resolves in either service with no path setup.

Only the names re-exported below are public. Everything else in ``redactor``
(the compiled patterns, the allowlists, ``_pseudonym``) is internal: a consumer
reaching past this list couples itself to a rule's implementation, and rules are
expected to change. See REDACTION_SPEC.md for what is redacted and why.
"""

from .redactor import (
    DEFAULT_KEY_PATH,
    KEY_SIZE,
    MIN_SWEEP_LEN,
    REDACTED,
    RE_ALREADY_DONE,
    RedactionState,
    load_key,
    pseudonym,
    redact,
)

__all__ = [
    "DEFAULT_KEY_PATH",
    "KEY_SIZE",
    "MIN_SWEEP_LEN",
    "REDACTED",
    "RE_ALREADY_DONE",
    "RedactionState",
    "load_key",
    "pseudonym",
    "redact",
]
