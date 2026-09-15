# -*- coding: utf-8 -*-

import logging
from typing import Literal


try:
    from redis import Redis
except ImportError:
    raise ImportError(
        """
        No required packages found, looks like you didn't install them:
        `pip install "jamlib[redis]"`
        """
    )

from jam.exceptions.jose import JamRedisListConfigurationError
from jam.lists.__base__ import BaseList


logger = logging.getLogger(__name__)


class RedisList(BaseList):
    """Redis-based JWT black/white list.

    Most optimal for production use with TTL support.

    Dependency required: `pip install jamlib[redis]`

    Attributes:
        _redis (Redis): Redis instance.
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
        redis_uri: str | Redis | None = None,
        redis: Redis | None = None,
        ttl: int | None = None,
    ) -> None:
        """Initialize RedisList.

        Args:
            type (Literal["white", "black"]): Type of list.
            prefix (str): Key prefix for Redis keys.
            redis_uri (str | Redis): Redis connection URI or Redis instance.
            redis (Redis | None): Redis instance (alias for redis_uri).
            ttl (int | None): Token TTL in seconds.
        """
        self._prefix = prefix
        self._ttl = ttl
        self.__list_type__ = type

        if isinstance(redis_uri, Redis):
            self._redis = redis_uri
        elif isinstance(redis, Redis):
            self._redis = redis
        elif redis_uri:
            self._redis = Redis.from_url(redis_uri, decode_responses=True)
        elif redis:
            self._redis = redis
        else:
            raise JamRedisListConfigurationError(
                message="redis_uri or redis must be provided"
            )

        logger.info(
            "Initialized RedisList with type=%s, prefix=%s, ttl=%s",
            type,
            prefix,
            ttl,
        )

    def _make_key(self, token: str) -> str:
        """Create Redis key with prefix."""
        return f"{self._prefix}:{token}"

    def add(self, token: str) -> None:
        """Add a single token to the list.

        Args:
            token (str): JWT token.
        """
        self._redis.set(self._make_key(token), "1", ex=self._ttl)
        logger.debug("Added token to %s list", self._prefix)

    def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens to the list.

        Args:
            tokens (list[str]): List of JWT tokens.
        """
        if not tokens:
            return
        pipe = self._redis.pipeline()
        for token in tokens:
            pipe.set(self._make_key(token), "1", ex=self._ttl)
        pipe.execute()
        logger.debug("Added %s tokens to %s list", len(tokens), self._prefix)

    def check(self, token: str) -> bool:
        """Check if a token is present in the list.

        Args:
            token (str): JWT token.

        Returns:
            bool: True if token exists in list.
        """
        return bool(self._redis.exists(self._make_key(token)))

    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens in the list.

        Args:
            tokens (list[str]): List of JWT tokens.

        Returns:
            dict[str, bool]: Mapping of token to presence.
        """
        if not tokens:
            return {}
        pipe = self._redis.pipeline()
        for token in tokens:
            pipe.exists(self._make_key(token))
        results = pipe.execute()
        return {token: bool(result) for token, result in zip(tokens, results)}

    def delete(self, token: str) -> None:
        """Remove a token from the list.

        Args:
            token (str): JWT token.
        """
        self._redis.delete(self._make_key(token))
        logger.debug("Deleted token from %s list", self._prefix)

    def delete_many(self, tokens: list[str]) -> None:
        """Remove multiple tokens from the list.

        Args:
            tokens (list[str]): List of JWT tokens.
        """
        if not tokens:
            return
        keys = [self._make_key(t) for t in tokens]
        self._redis.delete(*keys)
        logger.debug(
            "Deleted %s tokens from %s list", len(tokens), self._prefix
        )
