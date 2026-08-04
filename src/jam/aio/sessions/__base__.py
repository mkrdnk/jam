# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from collections.abc import Callable
import logging
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import JamSessionEmptyAESKey
from jam.utils.config_maker import __key_loader__


logger = logging.getLogger(__name__)


class BaseAsyncSessionModule(ABC):
    """Abstract base class for async session management modules."""

    def __init__(
        self,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> None:
        """Initialize the async session module."""
        self._id = id_factory
        self._sk_mark_symbol = "J$_"
        self._serializer = serializer
        if is_session_crypt and not session_aes_secret:
            raise JamSessionEmptyAESKey
        if is_session_crypt:
            assert session_aes_secret is not None
            if isinstance(session_aes_secret, str):
                session_aes_secret = __key_loader__(session_aes_secret)
            self._code_session_key = Fernet(session_aes_secret)

    def __encode_session_id__(self, data: str) -> str:
        """Encode the session using AES encryption."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session key encoding is not enabled.")
        return f"{self._sk_mark_symbol}{self._code_session_key.encrypt(data.encode()).decode()}"

    def __decode_session_id__(self, data: str) -> str:
        """Decode the session using AES decryption."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session key encoding is not enabled.")
        if not data.startswith(self._sk_mark_symbol):
            raise ValueError("Session key is not encoded or is invalid.")
        return self._code_session_key.decrypt(
            data[len(self._sk_mark_symbol) :].encode()
        ).decode()

    def __encode_session_id_if_needed__(self, data: str) -> str:
        """Encode the session ID if it is not already encoded."""
        if hasattr(self, "_code_session_key"):
            try:
                data = self.__encode_session_id__(data)
            except ValueError as e:
                logger.error(f"Failed to encode session ID: {e}")
            return data
        else:
            return data

    def __decode_session_id_if_needed__(self, data: str) -> str:
        """Decode the session ID if it is encoded."""
        if hasattr(self, "_code_session_key"):
            try:
                data = self.__decode_session_id__(data)
            except ValueError as e:
                logger.error(f"Failed to decode session ID: {e}")
            return data
        else:
            return data

    def __encode_session_data__(self, data: dict) -> str:
        """Encode session data."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session data encoding is not enabled.")

        data_json = self._serializer.dumps(data).decode("utf-8")
        return self.__encode_session_id__(data_json)

    def __decode_session_data__(self, data: str) -> dict:
        """Decode session data."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session key encoding is not enabled.")
        data = self.__decode_session_id__(data)
        return self._serializer.loads(data)

    @property
    def id(self) -> str:
        """Return the unique ID use id_factory."""
        return self._id()

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
