"""Example: anonymize a user dict the way an app would."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anonymizer import Anonymizer, rules
from anonymizer.presets import user_profile

user = {
    "user_id": "u-90210",
    "email": "olga.kovalenko@example.com",
    "phone": "380501112233",
    "full_name": "Olga Kovalenko",
    "birth_date": "1994-03-12",
    "age": 32,
    "zip": "01001",
    "password": "never-keep-this",
    "notes": "Call me at +380501112233 or olga.kovalenko@example.com",
    "profile": {"ip_address": "203.0.113.10", "bio": "Reach me at olga@example.com"},
}

def print_record(title: str, record: dict, indent: str = "  ") -> None:
    print(title)
    for key, value in record.items():
        if isinstance(value, dict):
            print(f"{indent}- {key}:")
            for nested_key, nested_value in value.items():
                print(f"{indent}  - {nested_key}: {nested_value}")
        elif isinstance(value, list):
            print(f"{indent}- {key}:")
            for item in value:
                print(f"{indent}  - {item}")
        else:
            print(f"{indent}- {key}: {value}")
    print()


# Fast path: common field names already mapped.
preset = user_profile("demo-secret-change-me")
print_record("preset:", preset.anonymize(user))

# Custom policy when your schema uses different keys.
anon = (
    Anonymizer("demo-secret-change-me")
    .field("user_id", rules.hash_id())
    .field("email", rules.mask_email())
    .field("phone", rules.mask_phone())
    .field("full_name", rules.mask_name())
    .field("birth_date", rules.drop())
    .field("age", rules.age_bucket())
    .field("zip", rules.zip_prefix())
    .field("password", rules.drop())
    .field("notes", rules.scrub_pii())
)
print_record("custom:", anon.anonymize(user))

#hui

