# -*- coding: utf-8 -*-

"""TinyDB-backed fingerprint token lists."""

from threading import RLock
from typing import Any, Literal


try:
    from tinydb import Query, TinyDB
except ImportError:
    raise ImportError(
        'JSON support requires `pip install "jamlib[json]"`.'
    ) from None

from jam.exceptions import JamConfigurationError
from jam.lists.__base__ import BaseList
from jam.lists._fingerprint import token_fingerprint


class JSONList(BaseList):
    """JSON file-based token allowlist or denylist."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        json_path: str = "whitelist.json",
        legacy_raw_keys: bool = True,
    ) -> None:
        """Initialize a JSON token list.

        Args:
            type (Literal["white", "black"]): Type of list.
            prefix (str): Key prefix retained for logging compatibility.
            json_path (str): Path to the TinyDB JSON file.
            legacy_raw_keys (bool): Read and delete legacy raw-token documents.

        Raises:
            JamConfigurationError: If legacy_raw_keys is not a boolean.
        """
        if not isinstance(legacy_raw_keys, bool):
            raise JamConfigurationError(
                message="legacy_raw_keys must be a boolean.",
                error_code="configuration.lists.invalid_legacy_raw_keys",
            )
        self._prefix = prefix
        self.__list_type__ = type
        self._legacy_raw_keys = legacy_raw_keys
        self._db = TinyDB(json_path)
        self._closed = False
        self._lock = RLock()

    def _v2_fingerprints(self) -> set[str]:
        """Read the fingerprints from valid v2 documents once."""
        with self._lock:
            return {
                document["fingerprint"]
                for document in self._db.all()
                if document.get("version") == 2
                and isinstance(document.get("fingerprint"), str)
            }

    def add(self, token: str) -> None:
        """Add a token if its fingerprint is not already stored."""
        self.add_many([token])

    def add_many(self, tokens: list[str]) -> None:
        """Add unique token fingerprints with one bulk insert."""
        fingerprints = list(
            dict.fromkeys(token_fingerprint(token) for token in tokens)
        )
        if not fingerprints:
            return
        with self._lock:
            existing = self._v2_fingerprints()
            documents = [
                {"version": 2, "fingerprint": fingerprint}
                for fingerprint in fingerprints
                if fingerprint not in existing
            ]
            if documents:
                self._db.insert_multiple(documents)

    def check(self, token: str) -> bool:
        """Check whether a token is present."""
        return self.check_many([token])[token]

    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens after one read of stored documents."""
        fingerprints = [token_fingerprint(token) for token in tokens]
        if not fingerprints:
            return {}
        with self._lock:
            documents = self._db.all()
            v2_fingerprints = {
                document["fingerprint"]
                for document in documents
                if document.get("version") == 2
                and isinstance(document.get("fingerprint"), str)
            }
            legacy_tokens: set[str] = set()
            if self._legacy_raw_keys:
                legacy_tokens = {
                    document["token"]
                    for document in documents
                    if isinstance(document.get("token"), str)
                }
        return {
            token: fingerprint in v2_fingerprints or token in legacy_tokens
            for token, fingerprint in zip(tokens, fingerprints)
        }

    def delete(self, token: str) -> None:
        """Remove a token from the list."""
        self.delete_many([token])

    def delete_many(self, tokens: list[str]) -> None:
        """Remove matching v2 and, when enabled, legacy documents once."""
        fingerprints = list(
            dict.fromkeys(token_fingerprint(token) for token in tokens)
        )
        if not fingerprints:
            return
        condition = (Query().version == 2) & Query().fingerprint.one_of(
            fingerprints
        )
        if self._legacy_raw_keys:
            condition = condition | Query().token.one_of(
                list(dict.fromkeys(tokens))
            )
        with self._lock:
            self._db.remove(condition)

    def close(self) -> None:
        """Close the TinyDB connection once."""
        with self._lock:
            if self._closed:
                return
            self._db.close()
            self._closed = True

    def __enter__(self) -> "JSONList":
        """Enter this JSON list's context."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Close the TinyDB connection when leaving its context."""
        self.close()
