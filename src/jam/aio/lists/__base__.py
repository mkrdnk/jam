# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Literal


class BaseAsyncList(ABC):
    """Asynchronous token allowlist or denylist."""

    __list_type__: Literal["black", "white"]

    @abstractmethod
    async def add(self, token: str) -> None:
        """Add a token."""
        raise NotImplementedError

    @abstractmethod
    async def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens."""
        raise NotImplementedError

    @abstractmethod
    async def check(self, token: str) -> bool:
        """Check whether a token is present."""
        raise NotImplementedError

    @abstractmethod
    async def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens."""
        raise NotImplementedError

    @abstractmethod
    async def delete(self, token: str) -> None:
        """Delete a token."""
        raise NotImplementedError

    @abstractmethod
    async def delete_many(self, tokens: list[str]) -> None:
        """Delete multiple tokens."""
        raise NotImplementedError
