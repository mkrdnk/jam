# -*- coding: utf-8 -*-

from typing import Literal


try:
    from redis.asyncio import Redis
except ImportError:
    raise ImportError("Redis support requires 'pip install jamlib[redis]'.")

from jam.aio.lists.__base__ import BaseAsyncList
from jam.exceptions.jose import JamRedisListConfigurationError


class RedisList(BaseAsyncList):
    """Redis-backed asynchronous token list."""

    def __init__(
        self,
        type: Literal["white", "black"],
        prefix: str = "jwt_list",
        redis_uri: str | Redis | None = None,
        ttl: int | None = None,
    ) -> None:
        """Initialize the Redis token list."""
        self.__list_type__ = type
        self._prefix = prefix
        self._ttl = ttl
        self._owns_client = isinstance(redis_uri, str)
        if isinstance(redis_uri, str):
            self._redis = Redis.from_url(redis_uri, decode_responses=True)
        elif redis_uri is not None:
            self._redis = redis_uri
        else:
            raise JamRedisListConfigurationError(
                message="redis_uri or redis must be provided"
            )

    def _make_key(self, token: str) -> str:
        return f"{self._prefix}:{token}"

    async def add(self, token: str) -> None:
        """Add a token."""
        await self._redis.set(self._make_key(token), "1", ex=self._ttl)

    async def add_many(self, tokens: list[str]) -> None:
        """Add multiple tokens in one Redis pipeline."""
        if not tokens:
            return
        async with self._redis.pipeline() as pipeline:
            for token in tokens:
                pipeline.set(self._make_key(token), "1", ex=self._ttl)
            await pipeline.execute()

    async def check(self, token: str) -> bool:
        """Check whether a token is present."""
        return bool(await self._redis.exists(self._make_key(token)))

    async def check_many(self, tokens: list[str]) -> dict[str, bool]:
        """Check multiple tokens in one Redis pipeline."""
        if not tokens:
            return {}
        async with self._redis.pipeline() as pipeline:
            for token in tokens:
                pipeline.exists(self._make_key(token))
            results = await pipeline.execute()
        return {token: bool(result) for token, result in zip(tokens, results)}

    async def delete(self, token: str) -> None:
        """Delete a token."""
        await self._redis.delete(self._make_key(token))

    async def delete_many(self, tokens: list[str]) -> None:
        """Delete multiple tokens."""
        if tokens:
            await self._redis.delete(
                *(self._make_key(token) for token in tokens)
            )

    async def aclose(self) -> None:
        """Close an internally-created Redis client."""
        if self._owns_client:
            await self._redis.aclose()
