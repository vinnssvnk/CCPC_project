"""Ready-made policies for common user-profile shapes."""

from __future__ import annotations

from . import rules
from .pipeline import Anonymizer


def user_profile(secret: str, *, enable_vault: bool = False) -> Anonymizer:
    """Sensible defaults for a typical app user object."""
    return Anonymizer(secret, enable_vault=enable_vault).fields(
        {
            "id": rules.hash_id(),
            "user_id": rules.hash_id(),
            "email": rules.mask_email(),
            "phone": rules.mask_phone(),
            "mobile": rules.mask_phone(),
            "name": rules.mask_name(),
            "full_name": rules.mask_name(),
            "first_name": rules.mask_name(),
            "last_name": rules.mask_name(),
            "ssn": rules.redact(),
            "password": rules.drop(),
            "password_hash": rules.drop(),
            "credit_card": rules.mask_card(),
            "card_number": rules.mask_card(),
            "birth_date": rules.drop(),
            "dob": rules.drop(),
            "date_of_birth": rules.drop(),
            "age": rules.age_bucket(),
            "zip": rules.zip_prefix(),
            "zipcode": rules.zip_prefix(),
            "postal_code": rules.zip_prefix(),
            "ip": rules.hash_id(prefix="ip_"),
            "ip_address": rules.hash_id(prefix="ip_"),
            "address": rules.redact(),
            "notes": rules.scrub_pii(),
            "comment": rules.scrub_pii(),
            "bio": rules.scrub_pii(),
        }
    )
