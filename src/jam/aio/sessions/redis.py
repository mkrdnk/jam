# -*- coding: utf-8 -*-

from collections.abc import Callable
import logging
import os
from uuid import uuid4

from redis.asyncio import Redis  # type: ignore[attr-defined]

from jam.aio.sessions.__base__ import BaseAsyncSessionModule
from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamSessionNotFound


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
        """
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
        logger.debug("Redis async connection established at %s", redis_uri)

        self.ttl = default_ttl
        self.session_path = redis_sessions_key

    async def _ping(self) -> bool:
        """Check if the Redis connection is alive."""
        try:
            return await self._redis.ping()  # type: ignore[not-async]
        except Exception as e:
            logger.error(f"Redis ping failed: {e}")
            return False

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
        logger.debug("Gen session: %s", session_id)

        # trying to encode data
        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        await self._redis.hset(  # type: ignore[not-async]
            name=f"{self.session_path}:{session_key}",
            key=session_id,
            value=dumps_data,
        )
        logger.debug("Set session %s successfully.", session_id)
        if self.ttl:
            await self._redis.hexpire(  # type: ignore[not-async]
                f"{self.session_path}:{session_key}", self.ttl, session_id
            )
            logger.debug(
                "Set TTL for session %s to %d seconds.",
                session_id,
                self.ttl,
            )

        return session_id

    async def get(self, session_id: str) -> dict | None:
        """Retrieve a session by its key or ID.

        Args:
            session_id (str): The session key or ID.

        Returns:
            dict | None: The session data if found, otherwise None.
        """
        logger.debug(f"Getting session with ID: {session_id}")
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        logger.debug(
            f"Decoded session key: {decoded_session_key[0]}, looking in Redis key: {self.session_path}:{decoded_session_key[0]}"
        )
        session = await self._redis.hget(  # type: ignore[not-async]
            name=f"{self.session_path}:{decoded_session_key[0]}",
            key=session_id,
        )
        if not session:
            logger.debug(f"Session {session_id} not found in Redis")
            return None

        try:
            loads_data = self.__decode_session_data__(session)
        except AttributeError:
            loads_data = self._serializer.loads(session)
        logger.debug(
            f"Session {session_id} found, data keys: {list(loads_data.keys()) if isinstance(loads_data, dict) else 'N/A'}"
        )
        del session

        return loads_data

    async def delete(self, session_id: str) -> None:
        """Delete a session by its ID.

        Args:
            session_id (str): The session ID.
        """
        logger.debug(f"Deleting session with ID: {session_id}")
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        deleted_count = await self._redis.hdel(  # type: ignore[not-async]
            f"{self.session_path}:{decoded_session_key[0]}",
            session_id,
        )
        logger.debug(
            f"Session {session_id} deleted from Redis, removed {deleted_count} field(s)"
        )

    async def clear(self, session_key: str) -> None:
        """Clear all sessions for a given session key.

        Args:
            session_key (str): The session key to clear.
        """
        await self._redis.delete(f"{self.session_path}:{session_key}")
        logger.debug(
            "All sessions for key '%s' cleared successfully.", session_key
        )

    async def update(self, session_id: str, data: dict) -> None:
        """Update an existing session with new data.

        Args:
            session_id (str): The ID of the session to update.
            data (dict): The new data to be stored in the session.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.
        """
        logger.debug(
            f"Updating session {session_id} with data keys: {list(data.keys())}"
        )
        decoded_session_key = self.__decode_session_id_if_needed__(
            session_id
        ).split(":", 1)
        if not await self.get(session_id):
            logger.warning(
                f"Attempted to update non-existent session {session_id}"
            )
            raise JamSessionNotFound(details={"session_id": session_id})

        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        await self._redis.hset(  # type: ignore[not-async]
            name=f"{self.session_path}:{decoded_session_key[0]}",
            key=session_id,
            value=dumps_data,
        )
        logger.debug(f"Session {session_id} updated successfully in Redis")

        if self.ttl:
            await self._redis.hexpire(
                f"{self.session_path}:{decoded_session_key[0]}",
                self.ttl,
                session_id,
            )
            logger.debug(
                "TTL for session %s reset to %d seconds.",
                session_id,
                self.ttl,
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
        session_data = await self.get(session_id)
        if not session_data:
            raise JamSessionNotFound(details={"session_id": session_id})

        new_session_id = await self.create(decoded_session_key[0], session_data)

        await self.delete(session_id)
        return new_session_id
