# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.sessions._codec import _SessionCodec


class BaseAsyncSessionModule(_SessionCodec, ABC):
    """Abstract base class for async session management modules."""

    def __init__(
        self,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> None:
        """Initialize the async session module."""
        super().__init__(
            id_factory=id_factory,
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            serializer=serializer,
        )

    @abstractmethod
    async def create(self, session_key: str, data: dict[str, Any]) -> str:
        """Create a new session with the given session key and data.

        Args:
            session_key (str): The key for the session.
            data (dict[str, Any]): The data to be stored in the session.

        Returns:
            str: The session ID.
        """
        raise NotImplementedError

    @abstractmethod
    async def get(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve a session by its key or ID.

        Args:
            session_id (str): The ID of the session.

        Returns:
            dict[str, Any] | None: The session data if found, otherwise None.
        """
        raise NotImplementedError

    @abstractmethod
    async def delete(self, session_id: str) -> None:
        """Delete a session by its key or ID.

        Args:
            session_id (str): The ID of the session.
        """
        raise NotImplementedError

    @abstractmethod
    async def update(self, session_id: str, data: dict[str, Any]) -> None:
        """Update an existing session with new data.

        Args:
            session_id (str): The ID of the session to update.
            data (dict[str, Any]): The new data to be stored in the session.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.
        """
        raise NotImplementedError

    @abstractmethod
    async def rework(self, session_id: str) -> str:
        """Rework a session and return its new ID.

        Args:
            session_id (str): The ID of the session to rework.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.

        Returns:
            str: The new session ID.
        """
        raise NotImplementedError

    @abstractmethod
    async def clear(self, session_key: str) -> None:
        """Clear all sessions by key.

        Args:
            session_key (str): The key for the sessions to clear.
        """
        raise NotImplementedError
