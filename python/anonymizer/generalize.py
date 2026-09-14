"""Reduce precision instead of hiding a value.

Generalization is the usual GDPR / HIPAA pattern for dates, ages,
and postal codes: keep utility for analytics, drop unique fingerprints.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

_YEAR = re.compile(r"(?:19|20)\d{2}")


def year_only(value: Any) -> str | None:
    """2024-06-18 / datetime -> '2024'."""
    if value is None or value == "":
        return value if value != "" else ""

    if isinstance(value, datetime):
        return str(value.year)
    if isinstance(value, date):
        return str(value.year)

    text = str(value).strip()
    digits = "".join(ch for ch in text if ch.isdigit())
    years = _YEAR.findall(text)
    if years and len(text) >= 4 and text[:4] == years[0] and (len(text) == 4 or text[4] in "-/. "):
        result = years[0]
    elif years:
        result = years[-1]
    elif len(digits) >= 4:
        result = digits[:4]
    else:
        result = "unknown"
    return result


def age_bucket(value: Any, *, width: int = 10) -> str | None:
    """32 -> '30-39'. Width is the bin size in years."""
    if value is None or value == "":
        return value if value != "" else ""

    try:
        age = int(float(value))
    except (TypeError, ValueError):
        return "unknown"

    if age < 0:
        return "unknown"
    if age >= 90:
        return "90+"

    start = (age // width) * width
    return f"{start}-{start + width - 1}"


def zip_prefix(value: Any, *, digits: int = 3) -> str | None:
    """Keep only the first N digits of a postal/ZIP code (US-style k-anonymity)."""
    if value is None or value == "":
        return value if value != "" else ""

    raw = "".join(ch for ch in str(value) if ch.isalnum())
    if not raw:
        return "***"
    return raw[:digits].upper() + ("*" * max(len(raw) - digits, 0))
