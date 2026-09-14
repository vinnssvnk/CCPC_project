"""
Quick start
-----------
Copy the ``anonymizer`` folder into your project (or install with pip).
No third-party packages are required — stdlib only.

    from anonymizer import Anonymizer, rules
    from anonymizer.presets import user_profile

    # Option A: one-liner for typical user records
    safe = user_profile("YOUR_SECRET").anonymize(user)

    # Option B: pick a rule per field
    anon = (
        Anonymizer("YOUR_SECRET", enable_vault=True)
        .field("email", rules.mask_email())
        .field("user_id", rules.hash_id())
        .field("phone", rules.tokenize())  # reversible via anon.vault
        .field("birth_date", rules.drop())
        .field("notes", rules.scrub_pii())
        .field("password", rules.drop())
    )
    safe = anon.anonymize(user)
    rows = anon.anonymize_many(users)

Which technique to use
----------------------
hash_id     HMAC-SHA256 fake id (full 64-char hex). Same input+secret -> same output.
mask_*      Keep shape (domain, last digits) for humans / dashboards.
year_only / age_bucket / zip_prefix
            Lower precision, keep stats. Prefer this over hashing dates.
redact      Replace with [REDACTED]. Use for SSN, street address, secrets.
drop        Delete the key. Use for passwords and date of birth.
tokenize    Replace with a token; look up original only inside this process
            via anon.vault.detokenize(token). Never log the vault.
scrub_pii   Scan free text for emails, phones, cards, IPs, SSNs.

Keep ``secret`` in an environment variable. Changing it invalidates all hashes.
"""
