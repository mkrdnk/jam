# -*- coding: utf-8 -*-

from collections.abc import Callable
import logging
import os
from typing import Any
from uuid import uuid4


try:
    from redis import Redis
except ImportError:
    raise ImportError(
        "Redis module is not installed. Please install it with 'pip install jamlib[redis]'."
    )

from redis.exceptions import RedisError

from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamError
from jam.sessions.__base__ import BaseSessionModule
from jam.sessions._codec import _normalize_session_payload
from jam.sessions._redis import (
    SESSION_WRITE,
    _check_write_result,
    _validate_ttl,
)


logger = logging.getLogger(__name__)


class RedisSessions(BaseSessionModule):
    """Redis session management module."""

    _SESSION_TYPE = "redis"
    _redis: Redis

    def __init__(
        self,
        session_type: str | None = None,
        sessions_type: str | None = None,
        redis_uri: str | Redis = "redis://localhost:6379/0",
        redis_sessions_key: str = "sessions",
        ttl: int | None = 3600,
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = os.getenv(
            "JAM_SESSION_AES_SECRET", None
        ),
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize the Redis session management module.

        Args:
            session_type (str | None): Session type for validation.
            sessions_type (str | None): Deprecated alias for session_type.
            redis_uri (str | Redis): The URI for the Redis server.
            redis_sessions_key (str): The key under which sessions are stored in Redis.
            ttl (Optional[int]): Default time-to-live for sessions in seconds. Defaults to 3600 seconds (1 hour).
            is_session_crypt (bool): If True, session keys will be encoded.
            session_aes_secret (Optional[bytes, str]): AES secret for encoding session keys. Required if `is_session_key_crypt` is True.
            id_factory (Callable[[], str], optional): A callable that generates unique IDs. Defaults to a UUID factory.
            serializer (Union[BaseEncoder, type[BaseEncoder]], optional): JSON encoder/decoder. Defaults to JsonEncoder.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.session".

        Raises:
            JamSessionEmptyAESKey: If 'is_session_crypt' is True and 'session_aes_secret' is not provided.
            ValueError: If the session type does not match the module type.
        """
        _validate_ttl(ttl)
        self._resolve_session_type(session_type, sessions_type)
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
        self._closed = False
        logger.debug("Redis session storage initialized")

        self.ttl = ttl
        self.session_path = redis_sessions_key

    def _ping(self) -> bool:
        """Check if the Redis connection is alive."""
        try:
            return self._redis.ping()  # type: ignore[return-value]
        except Exception as e:
            logger.error("Redis ping failed: %s", e)
            return False

    def _write(
        self, namespace: str, operation: str, old: str, new: str, data: str
    ) -> None:
        """Execute a session mutation and translate storage failures."""
        ttl = _validate_ttl(self.ttl) or 0
        try:
            result = self._redis.eval(
                SESSION_WRITE, 1, namespace, operation, old, new, data, ttl
            )
        except RedisError as exc:
            raise JamError(
                message="Redis session write failed.",
                error_code="sessions.storage_error",
            ) from exc
        _check_write_result(result)

    def create(self, session_key: str, data: dict) -> str:
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
        logger.debug("Creating session in Redis storage")

        # trying to encode data
        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        self._write(
            f"{self.session_path}:{session_key}",
            "create",
            "",
            session_id,
            dumps_data,
        )

        return session_id

    def get(self, session_id: str) -> dict | None:
        """Retrieve a session by its key or ID.

        Args:
            session_id (str): The session key or ID.

        Returns:
            dict | None: The session data if found, otherwise None.
        """
        logger.debug("Reading session from Redis storage")
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        logger.debug("Resolved session namespace in Redis storage")
        session = self._redis.hget(
            name=f"{self.session_path}:{decoded_session_key[0]}",
            key=session_id,
        )
        if session is None:
            logger.debug("Session not found in Redis storage")
            return None
        session = _normalize_session_payload(session)

        try:
            loads_data = self.__decode_session_data__(session)
        except AttributeError:
            loads_data = self._serializer.loads(session)
        logger.debug(
            "Found session in Redis storage with data_key_count=%d",
            (len(loads_data) if isinstance(loads_data, dict) else 0),
        )
        del session

        return loads_data

    def delete(self, session_id: str) -> None:
        """Delete a session by its ID.

        Args:
            session_id (str): The session ID.
        """
        logger.debug("Deleting session from Redis storage")
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        deleted_count = self._redis.hdel(
            f"{self.session_path}:{decoded_session_key[0]}",
            session_id,
        )
        logger.debug(
            "Deleted session from Redis storage, removed_field_count=%d",
            deleted_count,
        )

    def clear(self, session_key: str) -> None:
        """Clear all sessions for a given session key.

        Args:
            session_key (str): The session key to clear.
        """
        self._redis.delete(f"{self.session_path}:{session_key}")
        logger.debug("Cleared sessions from Redis storage")

    def update(self, session_id: str, data: dict) -> None:
        """Update an existing session with new data.

        Args:
            session_id (str): The ID of the session to update.
            data (dict): The new data to be stored in the session.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.
        """
        logger.debug(
            "Updating session in Redis storage with data_key_count=%d",
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

        self._write(
            f"{self.session_path}:{decoded_session_key[0]}",
            "update",
            session_id,
            session_id,
            dumps_data,
        )

    def rework(self, session_id: str) -> str:
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
        self._write(
            f"{self.session_path}:{decoded_session_key[0]}",
            "rework",
            session_id,
            new_session_id,
            "",
        )
        return new_session_id

    def close(self) -> None:
        """Close the Redis client when this backend created it."""
        if self._closed:
            return
        if self._owns_redis:
            self._redis.close()
        self._closed = True
