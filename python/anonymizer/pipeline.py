"""High-level API: map field names to rules, then anonymize dicts / lists.

The pipeline copies records by default so callers never lose originals.
Pass ``inplace=True`` only when you already work on a disposable copy.
"""

from __future__ import annotations

from typing import Any, Iterable, Iterator, Mapping

from .rules import RuleFn, _DROP
from .tokenize import TokenVault


class Anonymizer:
    """Apply a field-name policy to user records.

    Parameters
    ----------
    secret:
        HMAC key. Store it in an env var / secret manager, never in git.
    enable_vault:
        Turn on reversible tokenization for fields using ``rules.tokenize()``.
    default_rule:
        Optional rule for keys that have no explicit mapping.
        Leave ``None`` to copy unknown fields unchanged.
    """

    __slots__ = ("secret", "vault", "_rules", "_default")

    def __init__(
        self,
        secret: str,
        *,
        enable_vault: bool = False,
        default_rule: RuleFn | None = None,
        rules_map: Mapping[str, RuleFn] | None = None,
    ) -> None:
        if not secret:
            raise ValueError("secret must be a non-empty string")
        self.secret = secret
        self.vault = TokenVault(secret) if enable_vault else None
        self._rules: dict[str, RuleFn] = dict(rules_map or ())
        self._default = default_rule

    def field(self, name: str, rule: RuleFn) -> Anonymizer:
        """Register a rule. Returns self so you can chain calls."""
        self._rules[name] = rule
        return self

    def fields(self, mapping: Mapping[str, RuleFn]) -> Anonymizer:
        self._rules.update(mapping)
        return self

    def anonymize(
        self,
        record: Mapping[str, Any],
        *,
        inplace: bool = False,
        nested: bool = True,
    ) -> dict[str, Any]:
        """Anonymize one mapping. Nested dicts/lists are walked when ``nested``."""
        if inplace and isinstance(record, dict):
            target = record
            drop_keys: list[str] = []
            for key, value in tuple(target.items()):
                new_value = self._transform(key, value, nested)
                if new_value is _DROP:
                    drop_keys.append(key)
                else:
                    target[key] = new_value
            for key in drop_keys:
                del target[key]
            return target

        out: dict[str, Any] = {}
        for key, value in record.items():
            new_value = self._transform(key, value, nested)
            if new_value is not _DROP:
                out[key] = new_value
        return out

    def anonymize_many(
        self,
        records: Iterable[Mapping[str, Any]],
        *,
        inplace: bool = False,
        nested: bool = True,
    ) -> list[dict[str, Any]]:
        """Anonymize a batch. Prefer this over a Python loop in app code."""
        return [self.anonymize(row, inplace=inplace, nested=nested) for row in records]

    def iter_anonymize(
        self,
        records: Iterable[Mapping[str, Any]],
        *,
        nested: bool = True,
    ) -> Iterator[dict[str, Any]]:
        """Streaming variant for large files / generators."""
        for row in records:
            yield self.anonymize(row, nested=nested)

    def _transform(self, key: str, value: Any, nested: bool) -> Any:
        """Apply the rule for ``key``, walking containers instead of stringifying them."""
        explicit = key in self._rules
        rule = self._rules.get(key, self._default)

        if rule is not None and getattr(rule, "__name__", "") == "drop":
            return _DROP

        if nested and isinstance(value, dict) and not explicit:
            return self.anonymize(value, nested=True)

        if nested and isinstance(value, (list, tuple)):
            mapped = [self._transform(key, item, nested) for item in value]
            mapped = [item for item in mapped if item is not _DROP]
            return mapped if isinstance(value, list) else tuple(mapped)

        if rule is None:
            return self._walk(value) if nested else value
        return rule(value, self)

    def _walk(self, value: Any) -> Any:
        if isinstance(value, dict):
            return self.anonymize(value, nested=True)
        if isinstance(value, list):
            return [self._walk(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._walk(item) for item in value)
        return value
