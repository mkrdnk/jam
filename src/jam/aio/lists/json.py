# -*- coding: utf-8 -*-

import asyncio
from typing import Literal

from jam.aio.lists.__base__ import BaseAsyncList
from jam.lists.json import JSONList


class AsyncJSONList(BaseAsyncList):
    """Thread-adapted JSON token list."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        json_path: str = "whitelist.json",
    ) -> None:
        """Initialize the underlying synchronous JSON list."""
        self._list = JSONList(type=type, prefix=prefix, json_path=json_path)
        self.__list_type__ = type

    async def add(self, token: str) -> None:
        """Add a token without blocking the event loop."""
        await asyncio.to_thread(self._list.add, token)

    async def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens without blocking the event loop."""
        await asyncio.to_thread(self._list.add_many, tokens)

    async def check(self, token: str) -> bool:
        """Check a token without blocking the event loop."""
        return await asyncio.to_thread(self._list.check, token)

    async def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens without blocking the event loop."""
        return await asyncio.to_thread(self._list.check_many, tokens)

    async def delete(self, token: str) -> None:
        """Delete a token without blocking the event loop."""
        await asyncio.to_thread(self._list.delete, token)

    async def delete_many(self, tokens: list[str]) -> None:
        """Delete multiple tokens without blocking the event loop."""
        await asyncio.to_thread(self._list.delete_many, tokens)
