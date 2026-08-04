# -*- coding: utf-8 -*-

from typing import Literal

from jam.lists.__base__ import BaseList
from jam.logger import BaseLogger


class MemoryList(BaseList):
    """In-memory JWT black/white list.

    Suitable for development, testing, or when external storage is not needed.
    No TTL support - tokens persist until explicitly removed.

    Attributes:
        _storage (dict): Internal storage for tokens.

    Methods:
        add: add single token to list
        add_many: add multiple tokens to list
        check: check if token exists in list
        check_many: check multiple tokens in list
        delete: remove token from list
        delete_many: remove multiple tokens from list
    """

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        logger: BaseLogger | None = None,
    ) -> None:
        """Initialize MemoryList.

        Args:
            type (Literal["white", "black"]): Type of list.
            prefix (str): Key prefix for storage.
            logger (BaseLogger | None): Logger instance.
        """
        self._storage: dict[str, bool] = {}
        self._prefix = prefix
        self.__list_type__ = type
        self._logger = logger

    def add(self, token: str) -> None:
        """Add a single token to the list.

        Args:
            token (str): JWT token.
        """
        self._storage[token] = True
        if self._logger:
            self._logger.debug("Added token to %s list", self._prefix)

    def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens to the list.

        Args:
            tokens (list[str]): List of JWT tokens.
        """
        for token in tokens:
            self._storage[token] = True
        if self._logger:
            self._logger.debug(
                f"Added {len(tokens)} tokens to {self._prefix} list"
            )

    def check(self, token: str) -> bool:
        """Check if a token is present in the list.

        Args:
            token (str): JWT token.

        Returns:
            bool: True if token exists in list.
        """
        return token in self._storage

    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens in the list.

        Args:
            tokens (list[str]): List of JWT tokens.

        Returns:
            dict[str, bool]: Mapping of token to presence.
        """
        return {token: token in self._storage for token in tokens}

    def delete(self, token: str) -> None:
        """Remove a token from the list.

        Args:
            token (str): JWT token.
        """
        self._storage.pop(token, None)
        if self._logger:
            self._logger.debug("Deleted token from %s list", self._prefix)

    def delete_many(self, tokens: list[str]) -> None:
        """Remove multiple tokens from the list.

        Args:
            tokens (list[str]): List of JWT tokens.
        """
        for token in tokens:
            self._storage.pop(token, None)
        if self._logger:
            self._logger.debug(
                f"Deleted {len(tokens)} tokens from {self._prefix} list"
            )
