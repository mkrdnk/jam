# -*- coding: utf-8 -*-

"""Asynchronous Redis-backed fingerprint token lists."""

import asyncio
from typing import Any, Literal


try:
    from redis.asyncio import Redis
except ImportError:
    raise ImportError(
        'Redis support requires `pip install "jamlib[redis]"`.'
    ) from None

from jam.aio.lists.__base__ import BaseAsyncList
from jam.exceptions.jose import JamRedisListConfigurationError
from jam.lists._fingerprint import token_fingerprint


class RedisList(BaseAsyncList):
    """Redis-backed asynchronous token list."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        redis_uri: str | Redis | None = None,
        redis: Redis | None = None,
        ttl: int | None = None,
        legacy_raw_keys: bool = True,
    ) -> None:
        """Initialize an asynchronous Redis token list."""
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

        self.__list_type__ = type
        self._prefix = prefix
        self._ttl = ttl
        self._legacy_raw_keys = legacy_raw_keys
        self._closed = False
        self._close_lock = asyncio.Lock()

    def _make_key(self, token: str) -> str:
        """Build a v2 fingerprint key for a serialized token."""
        return f"{self._prefix}:v2:{token_fingerprint(token)}"

    def _make_legacy_key(self, token: str) -> str:
        """Build a pre-v2 raw-token storage key."""
        return f"{self._prefix}:{token}"

    async def add(self, token: str) -> None:
        """Add a token."""
        await self._redis.set(self._make_key(token), "1", ex=self._ttl)

    async def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens in one Redis pipeline."""
        keys = list(dict.fromkeys(self._make_key(token) for token in tokens))
        if not keys:
            return
        async with self._redis.pipeline() as pipeline:
            for key in keys:
                pipeline.set(key, "1", ex=self._ttl)
            await pipeline.execute()

    async def check(self, token: str) -> bool:
        """Check whether a token is present."""
        if (await self._redis.mget([self._make_key(token)]))[0] is not None:
            return True
        if self._legacy_raw_keys:
            legacy_key = self._make_legacy_key(token)
            return (await self._redis.mget([legacy_key]))[0] is not None
        return False

    async def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens with at most two Redis MGET commands."""
        keys = [self._make_key(token) for token in tokens]
        if not keys:
            return {}
        v2_values = await self._redis.mget(keys)
        result = {
            token: value is not None for token, value in zip(tokens, v2_values)
        }
        misses = [token for token in tokens if not result[token]]
        if self._legacy_raw_keys and misses:
            legacy_values = await self._redis.mget(
                [self._make_legacy_key(token) for token in misses]
            )
            result.update(
                {
                    token: value is not None
                    for token, value in zip(misses, legacy_values)
                }
            )
        return result

    async def delete(self, token: str) -> None:
        """Delete a token."""
        await self.delete_many([token])

    async def delete_many(self, tokens: list[str]) -> None:
        """Delete v2 and, when enabled, legacy keys in one Redis command."""
        keys = [self._make_key(token) for token in tokens]
        if not keys:
            return
        if self._legacy_raw_keys:
            keys.extend(self._make_legacy_key(token) for token in tokens)
        await self._redis.delete(*dict.fromkeys(keys))

    async def aclose(self) -> None:
        """Close an internally-created Redis client once."""
        async with self._close_lock:
            if self._closed:
                return
            if self._owns_client:
                await self._redis.aclose()
            self._closed = True

    async def __aenter__(self) -> "RedisList":
        """Enter this Redis list's asynchronous context."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Close an owned Redis client when leaving its context."""
        await self.aclose()
