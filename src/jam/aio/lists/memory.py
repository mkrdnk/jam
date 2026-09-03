# -*- coding: utf-8 -*-

from typing import Literal

from jam.aio.lists.__base__ import BaseAsyncList


class MemoryList(BaseAsyncList):
    """In-memory asynchronous token list."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
    ) -> None:
        """Initialize an empty token list."""
        self.__list_type__ = type
        self._prefix = prefix
        self._tokens: set[str] = set()

    async def add(self, token: str) -> None:
        """Add a token."""
        self._tokens.add(token)

    async def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens."""
        self._tokens.update(tokens)

    async def check(self, token: str) -> bool:
        """Check whether a token is present."""
        return token in self._tokens

    async def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens."""
        return {token: token in self._tokens for token in tokens}

    async def delete(self, token: str) -> None:
        """Delete a token."""
        self._tokens.discard(token)

    async def delete_many(self, tokens: list[str]) -> None:
        """Delete multiple tokens."""
        self._tokens.difference_update(tokens)
