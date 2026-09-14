"""
User-data anonymization toolkit.

Typical usage::

    from anonymizer import Anonymizer, rules

    anon = Anonymizer(secret="change-me-in-production")
    anon.field("email", rules.mask_email())
    anon.field("user_id", rules.hash_id())
    anon.field("phone", rules.mask_phone())
    anon.field("birth_date", rules.year_only())
    anon.field("notes", rules.scrub_pii())

    safe = anon.anonymize(user_record)
"""

from .pipeline import Anonymizer
from . import rules
from .detect import scrub_pii, find_pii
from .hashing import hash_value, hmac_sha256
from .masking import mask_email, mask_phone, mask_name, mask_card, redact
from .generalize import year_only, age_bucket, zip_prefix
from .presets import user_profile
from .tokenize import TokenVault

__all__ = [
    "Anonymizer",
    "rules",
    "scrub_pii",
    "find_pii",
    "hash_value",
    "hmac_sha256",
    "mask_email",
    "mask_phone",
    "mask_name",
    "mask_card",
    "redact",
    "year_only",
    "age_bucket",
    "zip_prefix",
    "TokenVault",
    "user_profile",
]

__version__ = "1.0.0"
