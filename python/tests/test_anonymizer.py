import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anonymizer import (
    Anonymizer,
    TokenVault,
    hash_value,
    hmac_sha256,
    mask_email,
    mask_name,
    mask_phone,
    rules,
    scrub_pii,
)
from anonymizer.generalize import age_bucket, year_only
from anonymizer.presets import user_profile


class HashTests(unittest.TestCase):
    def test_hmac_sha256_full_digest(self):
        digest = hmac_sha256("u-1", "secret-a")
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, hmac_sha256("u-1", "secret-a"))
        self.assertNotEqual(digest, hmac_sha256("u-1", "secret-b"))

    def test_stable_and_secret_dependent(self):
        a = hash_value("u-1", "secret-a")
        b = hash_value("u-1", "secret-a")
        c = hash_value("u-1", "secret-b")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("h_"))
        self.assertEqual(len(a), 2 + 64)

    def test_optional_truncate(self):
        short = hash_value("u-1", "s", length=16)
        self.assertEqual(len(short), 2 + 16)

    def test_none_passthrough(self):
        self.assertIsNone(hash_value(None, "s"))


class MaskTests(unittest.TestCase):
    def test_email(self):
        self.assertEqual(mask_email("john.doe@company.com"), "j***@company.com")

    def test_phone_keeps_last_four(self):
        self.assertTrue(mask_phone("380501112233").endswith("2233"))

    def test_name_initials(self):
        self.assertEqual(mask_name("Olga Kovalenko"), "O. K.")


class GeneralizeTests(unittest.TestCase):
    def test_year(self):
        self.assertEqual(year_only("1994-03-12"), "1994")
        self.assertEqual(year_only(date(1994, 3, 12)), "1994")
        self.assertEqual(year_only("03/12/1994"), "1994")
        self.assertEqual(year_only("12.03.1994"), "1994")

    def test_age_bucket(self):
        self.assertEqual(age_bucket(32), "30-39")


class DetectTests(unittest.TestCase):
    def test_scrub(self):
        text = scrub_pii("mail me at a@b.com and 4111 1111 1111 1111")
        self.assertIn("[EMAIL]", text)
        self.assertIn("[CARD]", text)
        self.assertNotIn("a@b.com", text)

    def test_iso_date_is_not_phone(self):
        text = scrub_pii("Appointment on 1994-03-12 at office")
        self.assertIn("1994-03-12", text)
        self.assertNotIn("[PHONE]", text)


class PipelineTests(unittest.TestCase):
    def test_token_vault_export(self):
        self.assertTrue(callable(TokenVault))

    def test_anonymize_and_drop(self):
        anon = (
            Anonymizer("s")
            .field("email", rules.mask_email())
            .field("password", rules.drop())
        )
        out = anon.anonymize({"email": "a@b.com", "password": "x", "ok": 1})
        self.assertEqual(out["email"], "a***@b.com")
        self.assertNotIn("password", out)
        self.assertEqual(out["ok"], 1)

    def test_nested_and_batch(self):
        anon = Anonymizer("s").field("email", rules.mask_email())
        rows = anon.anonymize_many(
            [{"email": "a@b.com", "meta": {"email": "c@d.com"}}]
        )
        self.assertEqual(rows[0]["email"], "a***@b.com")
        self.assertEqual(rows[0]["meta"]["email"], "c***@d.com")

    def test_list_valued_field(self):
        out = Anonymizer("s").field("email", rules.mask_email()).anonymize(
            {"email": ["a@b.com", "c@d.com"]}
        )
        self.assertEqual(out["email"], ["a***@b.com", "c***@d.com"])

    def test_default_rule_does_not_flatten_nested_dict(self):
        anon = Anonymizer("s", default_rule=rules.redact()).field(
            "email", rules.mask_email()
        )
        out = anon.anonymize({"email": "a@b.com", "profile": {"email": "c@d.com"}})
        self.assertIsInstance(out["profile"], dict)
        self.assertEqual(out["profile"]["email"], "c***@d.com")

    def test_tokenize_roundtrip(self):
        anon = Anonymizer("s", enable_vault=True).field("phone", rules.tokenize())
        out = anon.anonymize({"phone": "12345"})
        self.assertTrue(out["phone"].startswith("tok_"))
        self.assertEqual(len(out["phone"]), 4 + 64)
        self.assertEqual(anon.vault.detokenize(out["phone"]), "12345")

    def test_preset(self):
        out = user_profile("s").anonymize(
            {
                "email": "olga@example.com",
                "user_id": "u-1",
                "password": "secret",
                "birth_date": "1994-03-12",
                "age": 32,
            }
        )
        self.assertNotIn("password", out)
        self.assertNotIn("birth_date", out)
        self.assertEqual(out["age"], "30-39")
        self.assertTrue(out["user_id"].startswith("h_"))
        self.assertEqual(len(out["user_id"]), 2 + 64)


if __name__ == "__main__":
    unittest.main()
