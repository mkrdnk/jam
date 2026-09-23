# -*- coding: utf-8 -*-

"""Asynchronous TinyDB-backed fingerprint token lists."""

import asyncio
from typing import Any, Literal

from jam.aio.lists.__base__ import BaseAsyncList
from jam.lists.json import JSONList


class AsyncJSONList(BaseAsyncList):
    """Thread-adapted JSON token list with serialized database access."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        json_path: str = "whitelist.json",
        legacy_raw_keys: bool = True,
    ) -> None:
        """Initialize the underlying synchronous JSON list."""
        self._list = JSONList(
            type=type,
            prefix=prefix,
            json_path=json_path,
            legacy_raw_keys=legacy_raw_keys,
        )
        self.__list_type__ = type
        self._lock = asyncio.Lock()
        self._closed = False

    async def add(self, token: str) -> None:
        """Add a token without blocking the event loop."""
        async with self._lock:
            await asyncio.to_thread(self._list.add, token)

    async def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens without blocking the event loop."""
        async with self._lock:
            await asyncio.to_thread(self._list.add_many, tokens)

    async def check(self, token: str) -> bool:
        """Check a token without blocking the event loop."""
        async with self._lock:
            return await asyncio.to_thread(self._list.check, token)

    async def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens without blocking the event loop."""
        async with self._lock:
            return await asyncio.to_thread(self._list.check_many, tokens)

    async def delete(self, token: str) -> None:
        """Delete a token without blocking the event loop."""
        async with self._lock:
            await asyncio.to_thread(self._list.delete, token)

    async def delete_many(self, tokens: list[str]) -> None:
        """Delete multiple tokens without blocking the event loop."""
        async with self._lock:
            await asyncio.to_thread(self._list.delete_many, tokens)

    async def aclose(self) -> None:
        """Close the underlying JSON list once."""
        async with self._lock:
            if self._closed:
                return
            await asyncio.to_thread(self._list.close)
            self._closed = True

    async def __aenter__(self) -> "AsyncJSONList":
        """Enter this JSON list's asynchronous context."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Close the JSON list when leaving its context."""
        await self.aclose()
