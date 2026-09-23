# -*- coding: utf-8 -*-

"""In-memory fingerprint-backed token lists."""

from typing import Literal

from jam.lists.__base__ import BaseList
from jam.lists._fingerprint import token_fingerprint


class MemoryList(BaseList):
    """In-memory token allowlist or denylist."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
    ) -> None:
        """Initialize an empty fingerprint-backed token list.

        Args:
            type (Literal["white", "black"]): Type of list.
            prefix (str): Key prefix retained for compatibility.
        """
        self._storage: set[str] = set()
        self._prefix = prefix
        self.__list_type__ = type

    def add(self, token: str) -> None:
        """Add a single token to the list."""
        self._storage.add(token_fingerprint(token))

    def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens to the list."""
        fingerprints = [token_fingerprint(token) for token in tokens]
        self._storage.update(fingerprints)

    def check(self, token: str) -> bool:
        """Check if a token is present in the list."""
        return token_fingerprint(token) in self._storage

    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens in the list."""
        return {
            token: token_fingerprint(token) in self._storage for token in tokens
        }

    def delete(self, token: str) -> None:
        """Remove a token from the list."""
        self._storage.discard(token_fingerprint(token))

    def delete_many(self, tokens: list[str]) -> None:
        """Remove multiple tokens from the list."""
        fingerprints = [token_fingerprint(token) for token in tokens]
        self._storage.difference_update(fingerprints)
