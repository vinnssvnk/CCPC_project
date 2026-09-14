"""Benchmark typical user_profile anonymization."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from anonymizer.presets import user_profile  # noqa: E402

N = 3000
user = {
    "user_id": "u-90210",
    "email": "user@example.com",
    "phone": "380501112233",
    "full_name": "Ada Lovelace",
    "birth_date": "1994-03-12",
    "age": 32,
    "zip": "01001",
    "password": "x",
    "notes": "Call me at +380501112233 or user@example.com",
    "profile": {"ip_address": "203.0.113.10", "bio": "Reach me at user@example.com"},
}

anon = user_profile("bench-secret")
rows = [dict(user) for _ in range(N)]

t0 = time.perf_counter()
out = anon.anonymize_many(rows)
elapsed = time.perf_counter() - t0

print(f"records={N} total_s={elapsed:.4f} rec_per_s={N / elapsed:.0f} out_keys={list(out[0].keys())}")
