# -*- coding: utf-8 -*-

from collections.abc import Callable
import logging
import os
from uuid import uuid4

from redis.asyncio import Redis  # type: ignore[attr-defined]
from redis.exceptions import RedisError

from jam.aio.sessions.__base__ import BaseAsyncSessionModule
from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamError
from jam.sessions._codec import _normalize_session_payload
from jam.sessions._redis import (
    SESSION_WRITE,
    UNSET_TTL,
    _check_write_result,
    _UnsetTTL,
    _validate_ttl,
)


logger = logging.getLogger(__name__)


class RedisSessions(BaseAsyncSessionModule):
    """Async Redis session management module."""

    _redis: Redis

    def __init__(
        self,
        redis_uri: str | Redis = "redis://localhost:6379/0",
        redis_sessions_key: str = "sessions",
        default_ttl: int | None = 3600,
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = os.getenv(
            "JAM_SESSION_AES_SECRET", None
        ),
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        *,
        ttl: int | None | _UnsetTTL = UNSET_TTL,
    ) -> None:
        """Initialize the async Redis session management module.

        Args:
            redis_uri (str | Redis): The URI for the Redis server or Redis instance.
            redis_sessions_key (str): The key under which sessions are stored in Redis.
            default_ttl (Optional[int]): Default time-to-live for sessions in seconds. Defaults to 3600 seconds (1 hour).
            is_session_crypt (bool): If True, session keys will be encoded.
            session_aes_secret (Optional[bytes]): AES secret for encoding session keys. Required if `is_session_key_crypt` is True.
            id_factory (Callable[[], str], optional): A callable that generates unique IDs. Defaults to a UUID factory.
            serializer (Union[BaseEncoder, type[BaseEncoder]], optional): JSON encoder/decoder. Defaults to JsonEncoder.
            ttl: Canonical TTL; overrides default_ttl when explicitly supplied.
        """
        resolved_ttl = default_ttl if ttl is UNSET_TTL else ttl
        assert not isinstance(resolved_ttl, _UnsetTTL)
        _validate_ttl(resolved_ttl)
        super().__init__(
            id_factory=id_factory,
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            serializer=serializer,
        )
        if isinstance(redis_uri, str):
            self._redis = Redis.from_url(redis_uri, decode_responses=True)
            self._owns_redis = True
        else:
            self._redis = redis_uri
            self._owns_redis = False
        logger.debug("Async Redis session storage initialized")

        self.ttl = resolved_ttl
        self.session_path = redis_sessions_key

    async def _ping(self) -> bool:
        """Check if the Redis connection is alive."""
        try:
            return await self._redis.ping()  # type: ignore[not-async]
        except Exception as e:
            logger.error(f"Redis ping failed: {e}")
            return False

    async def _write(
        self, namespace: str, operation: str, old: str, new: str, data: str
    ) -> None:
        """Execute a session mutation and translate storage failures."""
        ttl = _validate_ttl(self.ttl) or 0
        try:
            result = await self._redis.eval(
                SESSION_WRITE, 1, namespace, operation, old, new, data, ttl
            )
        except RedisError as exc:
            raise JamError(
                message="Redis session write failed.",
                error_code="sessions.storage_error",
            ) from exc
        _check_write_result(result)

    async def create(self, session_key: str, data: dict) -> str:
        """Create a new session with the given session key and data.

        Args:
            session_key (str): The key for the session.
            data (dict): The data to be stored in the session.

        Returns:
            str: The unique ID of the created session.
        """
        session_id = self.__encode_session_id_if_needed__(
            f"{session_key}:{self.id}"
        )
        logger.debug("Creating session in async Redis storage")

        # trying to encode data
        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        await self._write(
            f"{self.session_path}:{session_key}",
            "create",
            "",
            session_id,
            dumps_data,
        )

        return session_id

    async def get(self, session_id: str) -> dict | None:
        """Retrieve a session by its key or ID.

        Args:
            session_id (str): The session key or ID.

        Returns:
            dict | None: The session data if found, otherwise None.
        """
        logger.debug("Reading session from async Redis storage")
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        logger.debug("Resolved session namespace in async Redis storage")
        session = await self._redis.hget(  # type: ignore[not-async]
            name=f"{self.session_path}:{decoded_session_key[0]}",
            key=session_id,
        )
        if session is None:
            logger.debug("Session not found in async Redis storage")
            return None
        session = _normalize_session_payload(session)

        try:
            loads_data = self.__decode_session_data__(session)
        except AttributeError:
            loads_data = self._serializer.loads(session)
        logger.debug(
            "Found session in async Redis storage with data_key_count=%d",
            len(loads_data) if isinstance(loads_data, dict) else 0,
        )
        del session

        return loads_data

    async def delete(self, session_id: str) -> None:
        """Delete a session by its ID.

        Args:
            session_id (str): The session ID.
        """
        logger.debug("Deleting session from async Redis storage")
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        deleted_count = await self._redis.hdel(  # type: ignore[not-async]
            f"{self.session_path}:{decoded_session_key[0]}",
            session_id,
        )
        logger.debug(
            "Deleted session from async Redis storage, removed_field_count=%d",
            deleted_count,
        )

    async def clear(self, session_key: str) -> None:
        """Clear all sessions for a given session key.

        Args:
            session_key (str): The session key to clear.
        """
        await self._redis.delete(f"{self.session_path}:{session_key}")
        logger.debug("Cleared sessions from async Redis storage")

    async def update(self, session_id: str, data: dict) -> None:
        """Update an existing session with new data.

        Args:
            session_id (str): The ID of the session to update.
            data (dict): The new data to be stored in the session.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.
        """
        logger.debug(
            "Updating session in async Redis storage with data_key_count=%d",
            len(data),
        )
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        await self._write(
            f"{self.session_path}:{decoded_session_key[0]}",
            "update",
            session_id,
            session_id,
            dumps_data,
        )

    async def rework(self, session_id: str) -> str:
        """Rework a session and return its new ID.

        Args:
            session_id (str): The ID of the session to rework.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.

        Returns:
            str: The new session ID.
        """
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        new_session_id = self.__encode_session_id_if_needed__(
            f"{decoded_session_key[0]}:{self.id}"
        )
        await self._write(
            f"{self.session_path}:{decoded_session_key[0]}",
            "rework",
            session_id,
            new_session_id,
            "",
        )
        return new_session_id

    async def aclose(self) -> None:
        """Close an internally-created Redis client."""
        if self._owns_redis:
            await self._redis.aclose()
