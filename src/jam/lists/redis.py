# -*- coding: utf-8 -*-

"""Redis-backed fingerprint token lists."""

from threading import Lock
from typing import Any, Literal


try:
    from redis import Redis
except ImportError:
    raise ImportError(
        'Redis support requires `pip install "jamlib[redis]"`.'
    ) from None

from jam.exceptions.jose import JamRedisListConfigurationError
from jam.lists.__base__ import BaseList
from jam.lists._fingerprint import token_fingerprint


class RedisList(BaseList):
    """Redis-backed token allowlist or denylist."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        redis_uri: str | Redis | None = None,
        redis: Redis | None = None,
        ttl: int | None = None,
        legacy_raw_keys: bool = True,
    ) -> None:
        """Initialize a Redis token list.

        Args:
            type (Literal["white", "black"]): Type of list.
            prefix (str): Prefix for Redis keys.
            redis_uri (str | Any | None): Redis URI or pre-created client.
            redis (Any | None): Pre-created Redis client.
            ttl (int | None): Positive token lifetime in seconds.
            legacy_raw_keys (bool): Read and delete pre-v2 raw-token keys.

        Raises:
            JamRedisListConfigurationError: If configuration is invalid.
        """
        if isinstance(ttl, bool) or (
            ttl is not None and (not isinstance(ttl, int) or ttl <= 0)
        ):
            raise JamRedisListConfigurationError(
                message="ttl must be a positive integer or None."
            )
        if not isinstance(legacy_raw_keys, bool):
            raise JamRedisListConfigurationError(
                message="legacy_raw_keys must be a boolean."
            )
        if redis_uri is not None and redis is not None:
            raise JamRedisListConfigurationError(
                message="Provide either redis_uri or redis, not both."
            )
        if isinstance(redis_uri, str):
            self._redis = Redis.from_url(redis_uri, decode_responses=True)
            self._owns_client = True
        elif redis_uri is not None:
            self._redis = redis_uri
            self._owns_client = False
        elif redis is not None:
            self._redis = redis
            self._owns_client = False
        else:
            raise JamRedisListConfigurationError(
                message="redis_uri or redis must be provided"
            )

        self._prefix = prefix
        self._ttl = ttl
        self._legacy_raw_keys = legacy_raw_keys
        self._closed = False
        self._close_lock = Lock()
        self.__list_type__ = type

    def _make_key(self, token: str) -> str:
        """Build a v2 fingerprint key for a serialized token."""
        return f"{self._prefix}:v2:{token_fingerprint(token)}"

    def _make_legacy_key(self, token: str) -> str:
        """Build a pre-v2 raw-token storage key."""
        return f"{self._prefix}:{token}"

    def add(self, token: str) -> None:
        """Add a single token to the list."""
        self._redis.set(self._make_key(token), "1", ex=self._ttl)

    def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens in one Redis pipeline."""
        keys = list(dict.fromkeys(self._make_key(token) for token in tokens))
        if not keys:
            return
        with self._redis.pipeline() as pipeline:
            for key in keys:
                pipeline.set(key, "1", ex=self._ttl)
            pipeline.execute()

    def check(self, token: str) -> bool:
        """Check whether a token is present."""
        if self._redis.mget([self._make_key(token)])[0] is not None:
            return True
        if self._legacy_raw_keys:
            return (
                self._redis.mget([self._make_legacy_key(token)])[0] is not None
            )
        return False

    def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens with at most two Redis MGET commands."""
        keys = [self._make_key(token) for token in tokens]
        if not keys:
            return {}
        v2_values = self._redis.mget(keys)
        result = {
            token: value is not None for token, value in zip(tokens, v2_values)
        }
        misses = [token for token in tokens if not result[token]]
        if self._legacy_raw_keys and misses:
            legacy_values = self._redis.mget(
                [self._make_legacy_key(token) for token in misses]
            )
            result.update(
                {
                    token: value is not None
                    for token, value in zip(misses, legacy_values)
                }
            )
        return result

    def delete(self, token: str) -> None:
        """Remove a token from the list."""
        self.delete_many([token])

    def delete_many(self, tokens: list[str]) -> None:
        """Remove v2 and, when enabled, legacy keys in one Redis command."""
        keys = [self._make_key(token) for token in tokens]
        if not keys:
            return
        if self._legacy_raw_keys:
            keys.extend(self._make_legacy_key(token) for token in tokens)
        self._redis.delete(*dict.fromkeys(keys))

    def close(self) -> None:
        """Close an internally-created Redis client once."""
        with self._close_lock:
            if self._closed:
                return
            if self._owns_client:
                self._redis.close()
            self._closed = True

    def __enter__(self) -> "RedisList":
        """Enter this Redis list's context."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Close an owned Redis client when leaving its context."""
        self.close()
