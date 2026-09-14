"""Find and scrub PII that hides inside free text.

Regexes are compiled once at import time. That is cheaper than compiling
on every call when you scan thousands of notes/comments.
"""

from __future__ import annotations

import re

_REPLACEMENTS = {
    "email": "[EMAIL]",
    "card": "[CARD]",
    "phone": "[PHONE]",
    "ipv4": "[IP]",
    "ssn": "[SSN]",
}


_PHONE_MIN_DIGITS = 10
_PHONE_MAX_DIGITS = 15

_COMBINED = re.compile(
    r"(?P<email>[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})"
    r"|(?P<card>\b(?:\d[ -]*?){13,19}\b)"
    r"|(?P<phone>(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?)?\d{3}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4})"
    r"|(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<ssn>\b\d{3}-\d{2}-\d{4}\b)",
    re.I,
)


def _digit_count(text: str) -> int:
    return sum(ch.isdigit() for ch in text)


def _is_phone_match(text: str) -> bool:
    n = _digit_count(text)
    return _PHONE_MIN_DIGITS <= n <= _PHONE_MAX_DIGITS


def find_pii(text: str) -> list[dict[str, str]]:
    """Return every match with its kind and span text (for audits)."""
    if not text:
        return []
    found: list[dict[str, str]] = []
    for match in _COMBINED.finditer(text):
        kind = match.lastgroup
        span = match.group(0)
        if kind == "phone" and not _is_phone_match(span):
            continue
        if kind:
            found.append({"kind": kind, "value": span})
    return found


def scrub_pii(value: str | None, replacements: dict[str, str] | None = None) -> str | None:
    """Replace detected PII in a string with placeholders."""
    if value is None:
        return None
    if value == "":
        return ""

    if "@" not in value and not any(ch.isdigit() for ch in value):
        return value

    labels = replacements or _REPLACEMENTS

    def _sub(match: re.Match[str]) -> str:
        kind = match.lastgroup or "pii"
        span = match.group(0)
        if kind == "phone" and not _is_phone_match(span):
            return span
        return labels.get(kind, f"[{kind.upper()}]")

    return _COMBINED.sub(_sub, value)
