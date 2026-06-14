"""
Canonical (deterministic) JSON serialization.

Signatures must be computed over bytes that are reproducible on every machine,
or verification breaks. We serialize with:

  * keys sorted lexicographically (by Unicode code point),
  * the most compact separators (no insignificant whitespace),
  * UTF-8 encoding, and
  * `ensure_ascii=False` so non-ASCII text is encoded once, identically.

This is a pragmatic subset of RFC 8785 (JSON Canonicalization Scheme).

IMPORTANT: signed payloads MUST NOT contain floating-point numbers. Float
formatting is not portable across languages and would make signatures fragile.
Use integers or strings. `canonicalize` raises on a float to enforce this at
signing time rather than letting a subtle bug ship.
"""

from __future__ import annotations

import json
from typing import Any


def _reject_floats(obj: Any) -> None:
    """Recursively assert there are no floats in a payload destined for signing."""
    if isinstance(obj, float):
        raise ValueError(
            "canonical: floats are forbidden in signed payloads "
            "(non-portable formatting). Use an int or a string."
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("canonical: object keys must be strings")
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def canonicalize(obj: Any) -> bytes:
    """Return the canonical UTF-8 byte encoding of a JSON-compatible object."""
    _reject_floats(obj)
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def canonical_str(obj: Any) -> str:
    """Canonical form as a `str` (for display / embedding)."""
    return canonicalize(obj).decode("utf-8")
