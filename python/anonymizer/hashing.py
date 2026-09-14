"""Keyed HMAC-SHA256 for identifiers.

HMAC (Hash-based Message Authentication Code) binds the digest to a
secret. Without that secret, rainbow tables and cross-dataset matching
do not work. The same input + secret always yields the same hex digest,
so joins across tables still work.

The default is the full 64-character SHA-256 hex digest. Pass ``length``
only if you must shorten IDs for storage (that weakens collision resistance).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

_templates: dict[bytes, hmac.HMAC] = {}


def hmac_sha256(value: str, secret: str | bytes) -> str:
    """Return the full HMAC-SHA256 hex digest of ``value``."""
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    tmpl = _templates.get(key)
    if tmpl is None:
        tmpl = hmac.new(key, digestmod=hashlib.sha256)
        _templates[key] = tmpl
    hasher = tmpl.copy()
    hasher.update(value.encode("utf-8"))
    return hasher.hexdigest()


def hash_value(
    value: Any,
    secret: str | bytes,
    *,
    length: int | None = None,
    prefix: str = "h_",
) -> str | None:
    """HMAC-SHA256 of ``value``, optionally truncated, with a prefix.

    Empty / None values pass through unchanged so missing fields stay missing.
    """
    if value is None:
        return None
    text = str(value)
    if text == "":
        return ""

    digest = hmac_sha256(text, secret)
    if length is not None and 0 < length < len(digest):
        digest = digest[:length]
    return f"{prefix}{digest}" if prefix else digest
