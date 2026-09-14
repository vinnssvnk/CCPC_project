"""Human-readable masking: hide most of a value, keep a hint of shape.

Use masking when analysts still need to *see* that a field existed
(e.g. an email domain for support stats). Use hashing when you need
stable joins. Use redaction when nothing of the original should remain.
"""

from __future__ import annotations

from typing import Any


def _s(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else ""


def mask_email(value: Any, *, keep_domain: bool = True) -> str | None:
    """john.doe@company.com -> j***@company.com"""
    text = _s(value)
    if not text:
        return text

    if "@" not in text:
        return mask_generic(text)

    local, _, domain = text.partition("@")
    shown = local[0] if local else "*"
    masked_local = shown + "***"
    return f"{masked_local}@{domain}" if keep_domain else f"{masked_local}@***"


def mask_phone(value: Any, *, last: int = 4) -> str | None:
    """+1-202-555-0147 -> ********0147 (digits only, last N kept)."""
    text = _s(value)
    if not text:
        return text

    digits = "".join(ch for ch in text if ch.isdigit())
    if not digits:
        return "***"

    keep = digits[-last:] if last < len(digits) else digits
    hidden = max(len(digits) - len(keep), 0)
    return ("*" * hidden) + keep


def mask_name(value: Any) -> str | None:
    """Olga Kovalenko -> O. K."""
    text = _s(value)
    if not text:
        return text

    parts = [p for p in text.split() if p]
    if not parts:
        return "***"
    return " ".join(f"{p[0].upper()}." for p in parts)


def mask_card(value: Any, *, last: int = 4) -> str | None:
    """4111111111111111 -> **** **** **** 1111"""
    text = _s(value)
    if not text:
        return text

    digits = "".join(ch for ch in text if ch.isdigit())
    if len(digits) < 12:
        return mask_generic(text)

    tail = digits[-last:]
    groups = ["****"] * ((len(digits) - last + 3) // 4)
    if groups:
        groups[-1] = tail.rjust(4, "*")
    return " ".join(groups)


def mask_generic(value: Any, *, keep_start: int = 1, keep_end: int = 1) -> str | None:
    """Keep a few edge characters, replace the middle with ***."""
    text = _s(value)
    if not text:
        return text
    if len(text) <= keep_start + keep_end:
        return "*" * len(text)
    return f"{text[:keep_start]}***{text[-keep_end:]}"


def redact(value: Any, placeholder: str = "[REDACTED]") -> str | None:
    """Replace any non-empty value with a constant placeholder."""
    text = _s(value)
    if text is None:
        return None
    if text == "":
        return ""
    return placeholder
