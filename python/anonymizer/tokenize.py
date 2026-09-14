"""Reversible tokenization with an in-memory vault.

Tokenization is for pipelines where a *trusted* service must later
map a token back to the original (e.g. customer support). The vault
must never be shipped to logs, analytics, or third parties.

Tokens themselves are HMAC hashes, so leaking the token table without
the secret still does not reveal originals stored elsewhere.
"""

from __future__ import annotations

from typing import Any

from .hashing import hash_value


class TokenVault:
    """Bidirectional map: original <-> token.

    Thread-unsafe by design. Create one vault per process/job.
    Persist ``dump()`` yourself if you need durability.
    """

    __slots__ = ("_secret", "_fwd", "_rev")

    def __init__(self, secret: str) -> None:
        self._secret = secret
        self._fwd: dict[str, str] = {}
        self._rev: dict[str, str] = {}

    def tokenize(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value)
        if text == "":
            return ""

        existing = self._fwd.get(text)
        if existing is not None:
            return existing

        token = hash_value(text, self._secret, prefix="tok_")
        # Extremely unlikely collision; append a counter if it happens.
        if token in self._rev and self._rev[token] != text:
            token = f"{token}{len(self._fwd):x}"

        self._fwd[text] = token
        self._rev[token] = text
        return token

    def detokenize(self, token: str | None) -> str | None:
        if token is None or token == "":
            return token
        return self._rev.get(token)

    def dump(self) -> dict[str, str]:
        """Return a copy of original -> token (keep this file encrypted)."""
        return dict(self._fwd)

    def load(self, mapping: dict[str, str]) -> None:
        self._fwd.update(mapping)
        self._rev.update({token: original for original, token in mapping.items()})

    def __len__(self) -> int:
        return len(self._fwd)
