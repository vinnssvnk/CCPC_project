"""Named field rules used by :class:`anonymizer.pipeline.Anonymizer`.

Each factory returns a small callable ``(value, ctx) -> anonymized``.
Keeping rules as functions (not a huge class hierarchy) makes them
cheap to compose and easy to unit-test in isolation.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from . import detect, generalize, hashing, masking


class RuleContext(Protocol):
    secret: str
    vault: Any


RuleFn = Callable[[Any, RuleContext], Any]


def hash_id(*, length: int | None = None, prefix: str = "h_") -> RuleFn:
    """HMAC-SHA256 identifier. ``length`` truncates the hex digest (optional)."""

    def apply(value: Any, ctx: RuleContext) -> Any:
        return hashing.hash_value(value, ctx.secret, length=length, prefix=prefix)

    apply.__name__ = "hash_id"
    return apply


def mask_email(*, keep_domain: bool = True) -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return masking.mask_email(value, keep_domain=keep_domain)

    apply.__name__ = "mask_email"
    return apply


def mask_phone(*, last: int = 4) -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return masking.mask_phone(value, last=last)

    apply.__name__ = "mask_phone"
    return apply


def mask_name() -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return masking.mask_name(value)

    apply.__name__ = "mask_name"
    return apply


def mask_card() -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return masking.mask_card(value)

    apply.__name__ = "mask_card"
    return apply


def redact(placeholder: str = "[REDACTED]") -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return masking.redact(value, placeholder=placeholder)

    apply.__name__ = "redact"
    return apply


def year_only() -> RuleFn:
    """
    Replace any recognized date/datetime with just "YYYY", or '****' if unparseable.
    """

    def apply(value: Any, ctx: RuleContext) -> Any:
        try:
            year = generalize.year_only(value)
            # Only keep year as a 4-digit, otherwise redact.
            if isinstance(year, str) and len(year) == 4 and year.isdigit():
                return year
        except Exception:
            pass
        return "****"

    apply.__name__ = "year_only"
    return apply

def age_bucket(*, width: int = 10) -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return generalize.age_bucket(value, width=width)

    apply.__name__ = "age_bucket"
    return apply


def zip_prefix(*, digits: int = 3) -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        return generalize.zip_prefix(value, digits=digits)

    apply.__name__ = "zip_prefix"
    return apply


def scrub_pii() -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        if value is None:
            return None
        return detect.scrub_pii(str(value))

    apply.__name__ = "scrub_pii"
    return apply


def tokenize() -> RuleFn:
    def apply(value: Any, ctx: RuleContext) -> Any:
        if ctx.vault is None:
            raise RuntimeError("tokenize() needs Anonymizer(..., enable_vault=True)")
        return ctx.vault.tokenize(value)

    apply.__name__ = "tokenize"
    return apply


def drop() -> RuleFn:
    """Remove the field from the output entirely."""

    def apply(value: Any, ctx: RuleContext) -> Any:
        return _DROP

    apply.__name__ = "drop"
    return apply


class _DropSentinel:
    __slots__ = ()


_DROP = _DropSentinel()
