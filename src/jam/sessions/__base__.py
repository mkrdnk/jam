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
from jam.utils.config_meta import ConfigMeta


logger = logging.getLogger(__name__)


class BaseSessionModule(ABC, metaclass=ConfigMeta):
    """Abstract base class for session management modules.

    You can create your own module for sessions. For example:

    ```python
    from jam.sessions import BaseSessionModule

    class CustomSessionModule(BaseSessionModule):
        def __init__(self, some_param: str) -> None:
            super().__init__(
                is_session_crypt=True,
                session_aes_secret=b'your-32-byte-base64-encoded-key'
            )

        # Your initialization code here
        def create(session_key: str) -> str:
            ...

        def get(session_id: str) -> dict:
            ...

        def delete(session_id: str) -> None:
            ...

        def update(session_id: str, data: dict) -> None:
            ...

        def rework(session_id: str) -> str:
            ...

        def clear(session_key: str) -> None:
            ...
    ```
    """

    _SESSION_TYPE: str
    _CONFIG_POINTER: str = "jam.session"

    @classmethod
    def _resolve_session_type(
        cls, session_type: str | None, sessions_type: str | None
    ) -> str | None:
        """Resolve and validate the session type.

        `sessions_type` is kept as a deprecated alias for `session_type`.

        Args:
            session_type (str | None): Session type.
            sessions_type (str | None): Deprecated alias.

        Raises:
            ValueError: If the resolved type does not match the module type.

        Returns:
            str | None: The resolved session type.
        """
        if session_type is None and sessions_type is not None:
            session_type = sessions_type
        if session_type is not None and session_type != cls._SESSION_TYPE:
            raise ValueError(
                f"Unknown session_type: {session_type}. "
                f"{cls.__name__} expects '{cls._SESSION_TYPE}'."
            )
        return session_type

    def __init__(
        self,
        session_type: str | None = None,
        sessions_type: str | None = None,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Class constructor.

        Args:
            session_type (str | None): Session type for validation.
            sessions_type (str | None): Deprecated alias for session_type.
            id_factory (Callable[str], optional): A callable that generates unique IDs. Defaults to a UUID factory.
            is_session_crypt (bool, optional): If True, session keys will be encoded. Defaults to False.
            session_aes_secret (Optional[bytes, str], optional): AES secret for encoding session keys.
            serializer (Union[BaseEncoder, type[BaseEncoder]], optional): JSON encoder/decoder. Defaults to JsonEncoder.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.session".

        Raises:
            JamSessionEmptyAESKey: If 'is_session_crypt' is True and 'session_aes_secret' is not provided.
            ValueError: If the session type does not match the module type.
        """
        self._resolve_session_type(session_type, sessions_type)
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
                logger.error("Failed to encode session ID: %s", e)
            return data
        else:
            return data

    def __decode_session_id_if_needed__(self, data: str) -> str:
        """Decode the session ID if it is encoded."""
        if hasattr(self, "_code_session_key"):
            try:
                data = self.__decode_session_id__(data)
            except ValueError as e:
                logger.error("Failed to decode session ID: %s", e)
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
    def create(self, session_key: str, data: dict[str, Any]) -> str:
        """Create a new session with the given session key and data.

        Args:
            session_key (str): The key for the session.
            data (dict): The data to be stored in the session.
        """
        raise NotImplementedError

    @abstractmethod
    def get(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve a session by its key or ID.

        Args:
            session_id (str): The ID of the session.

        Returns:
            dict | None: The session data if found, otherwise None.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(self, session_id: str) -> None:
        """Delete a session by its key or ID.

        Args:
            session_id (str): The ID of the session.
        """
        raise NotImplementedError

    @abstractmethod
    def update(self, session_id: str, data: dict[str, Any]) -> None:
        """Update an existing session with new data.

        Args:
            session_id (str): The ID of the session to update.
            data (dict): The new data to be stored in the session.

        Raises:
            JamSessionNotFound: If the session with the given ID does not exist.
        """
        raise NotImplementedError

    @abstractmethod
    def rework(self, session_id: str) -> str:
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
    def clear(self, session_key: str) -> None:
        """Clear all sessions by key.

        Args:
            session_key (str): The key for the sessions to clear.
        """
        raise NotImplementedError
