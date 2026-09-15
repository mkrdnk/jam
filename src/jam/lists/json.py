# -*- coding: utf-8 -*-

import logging
from typing import Literal


try:
    from tinydb import Query, TinyDB
except ImportError:
    raise ImportError(
        """
        No required packages found, looks like you didn't install them:
        `pip install "jamlib[json]"`
        """
    )

from jam.lists.__base__ import BaseList


logger = logging.getLogger(__name__)


class JSONList(BaseList):
    """JSON file-based JWT black/white list.

    Not recommended for blacklists - no TTL support, user must manage token lifetime.

    Dependency required: `pip install jamlib[json]`

    Attributes:
        _db (TinyDB): TinyDB instance.
        _prefix (str): Key prefix.

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
        json_path: str = "whitelist.json",
    ) -> None:
        """Initialize JSONList.

        Args:
            type (Literal["white", "black"]): Type of list.
            prefix (str): Key prefix (used for logging).
            json_path (str): Path to JSON file.
        """
        self._prefix = prefix
        self.__list_type__ = type
        self._db = TinyDB(json_path)
        logger.info("Initialized JSONList at %s", json_path)

    def add(self, token: str) -> None:
        """Add a single token to the list.

        Args:
            token (str): JWT token.
        """
        self._db.insert({"token": token})
        logger.debug("Added token to %s list", self._prefix)

    def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens to the list.

        Args:
            tokens (list[str]): List of JWT tokens.
        """
        for token in tokens:
            self._db.insert({"token": token})
        logger.debug("Added %s tokens to %s list", len(tokens), self._prefix)

    def check(self, token: str) -> bool:
        """Check if a token is present in the list.

        Args:
            token (str): JWT token.

        Returns:
            bool: True if token exists in list.
        """
        cond = Query()
        return bool(self._db.search(cond.token == token))

    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens in the list.

        Args:
            tokens (list[str]): List of JWT tokens.

        Returns:
            dict[str, bool]: Mapping of token to presence.
        """
        result = {}
        cond = Query()
        for token in tokens:
            result[token] = bool(self._db.search(cond.token == token))
        return result

    def delete(self, token: str) -> None:
        """Remove a token from the list.

        Args:
            token (str): JWT token.
        """
        cond = Query()
        self._db.remove(cond.token == token)
        logger.debug("Deleted token from %s list", self._prefix)

    def delete_many(self, tokens: list[str]) -> None:
        """Remove multiple tokens from the list.

        Args:
            tokens (list[str]): List of JWT tokens.
        """
        cond = Query()
        for token in tokens:
            self._db.remove(cond.token == token)
        logger.debug(
            "Deleted %s tokens from %s list", len(tokens), self._prefix
        )
