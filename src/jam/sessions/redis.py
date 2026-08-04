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

from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamSessionNotFound
from jam.sessions.__base__ import BaseSessionModule


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
        self._resolve_session_type(session_type, sessions_type)
        super().__init__(
            id_factory=id_factory,
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            serializer=serializer,
        )
        if isinstance(redis_uri, str):
            self._redis = Redis.from_url(redis_uri, decode_responses=True)
        else:
            self._redis = redis_uri
        logger.debug("Redis connection established at %s", redis_uri)

        self.ttl = ttl
        self.session_path = redis_sessions_key

    def _ping(self) -> bool:
        """Check if the Redis connection is alive."""
        try:
            return self._redis.ping()  # type: ignore[return-value]
        except Exception as e:
            logger.error("Redis ping failed: %s", e)
            return False

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
        logger.debug("Gen session: %s", session_id)

        # trying to encode data
        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        self._redis.hset(
            name=f"{self.session_path}:{session_key}",
            key=session_id,
            value=dumps_data,
        )
        logger.debug("Set session %s successfully.", session_id)
        if self.ttl:
            self._redis.hexpire(
                f"{self.session_path}:{session_key}", self.ttl, session_id
            )
            logger.debug(
                "Set TTL for session %s to %d seconds.",
                session_id,
                self.ttl,
            )

        return session_id

    def get(self, session_id: str) -> dict | None:
        """Retrieve a session by its key or ID.

        Args:
            session_id (str): The session key or ID.

        Returns:
            dict | None: The session data if found, otherwise None.
        """
        logger.debug("Getting session with ID: %s", session_id)
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        logger.debug(
            "Decoded session key: %s, looking in Redis key: %s:%s",
            decoded_session_key[0],
            self.session_path,
            decoded_session_key[0],
        )
        session = self._redis.hget(
            name=f"{self.session_path}:{decoded_session_key[0]}",
            key=session_id,
        )
        if not session:
            logger.debug("Session %s not found in Redis", session_id)
            return None

        try:
            loads_data = self.__decode_session_data__(session)  # type: ignore[arg-type]
        except AttributeError:
            loads_data = self._serializer.loads(session)  # type: ignore[arg-type]
        logger.debug(
            "Session %s found, data keys: %s",
            session_id,
            (
                list(loads_data.keys())
                if isinstance(loads_data, dict)
                else "N/A"
            ),
        )
        del session

        return loads_data

    def delete(self, session_id: str) -> None:
        """Delete a session by its ID.

        Args:
            session_id (str): The session ID.
        """
        logger.debug("Deleting session with ID: %s", session_id)
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        deleted_count = self._redis.hdel(
            f"{self.session_path}:{decoded_session_key[0]}",
            session_id,
        )
        logger.debug(
            "Session %s deleted from Redis, removed %s field(s)",
            session_id,
            deleted_count,
        )

    def clear(self, session_key: str) -> None:
        """Clear all sessions for a given session key.

        Args:
            session_key (str): The session key to clear.
        """
        self._redis.delete(f"{self.session_path}:{session_key}")
        logger.debug(
            "All sessions for key '%s' cleared successfully.", session_key
        )

    def update(self, session_id: str, data: dict) -> None:
        """Update an existing session with new data.

        Args:
            session_id (str): The ID of the session to update.
            data (dict): The new data to be stored in the session.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.
        """
        logger.debug(
            "Updating session %s with data keys: %s",
            session_id,
            list(data.keys()),
        )
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        if not self.get(session_id):
            logger.warning(
                "Attempted to update non-existent session %s", session_id
            )
            raise JamSessionNotFound(details={"session_id": session_id})

        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        self._redis.hset(
            name=f"{self.session_path}:{decoded_session_key[0]}",
            key=session_id,
            value=dumps_data,
        )
        logger.debug("Session %s updated successfully in Redis", session_id)

        if self.ttl:
            self._redis.hexpire(
                f"{self.session_path}:{decoded_session_key[0]}",
                self.ttl,
                session_id,
            )
            logger.debug(
                "TTL for session %s reset to %d seconds.",
                session_id,
                self.ttl,
            )

    # TODO: Optimize this method
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
        session_data = self.get(session_id)
        if not session_data:
            raise JamSessionNotFound(details={"session_id": session_id})

        new_session_id = self.create(decoded_session_key[0], session_data)

        self.delete(session_id)
        return new_session_id
