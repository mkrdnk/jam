# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Literal


class BaseList(ABC):
    """Storage contract for serialized-token allowlists and denylists.

    List entries are complete serialized tokens, not token identifiers such as
    a JWT ``jti`` claim. A ``black`` list denies present tokens, while a
    ``white`` list denies absent tokens.
    """

    __list_type__: Literal["black", "white"]

    @abstractmethod
    def add(self, token: str) -> None:
        """Add a single token to the list."""
        raise NotImplementedError

    @abstractmethod
    def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens to the list."""
        raise NotImplementedError

    @abstractmethod
    def check(self, token: str) -> bool:
        """Check if a token is present in the list."""
        raise NotImplementedError

    @abstractmethod
    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens in the list."""
        raise NotImplementedError

    @abstractmethod
    def delete(self, token: str) -> None:
        """Remove a single token from the list."""
        raise NotImplementedError

    @abstractmethod
    def delete_many(self, tokens: list[str]) -> None:
        """Remove multiple tokens from the list."""
        raise NotImplementedError
