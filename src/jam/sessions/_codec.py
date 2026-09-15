# -*- coding: utf-8 -*-

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


class _SessionCodec:
    """Shared session identifier and payload serialization."""

    def __init__(
        self,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> None:
        self._id = id_factory
        self._sk_mark_symbol = "J$_"
        self._serializer = serializer
        if is_session_crypt and not session_aes_secret:
            raise JamSessionEmptyAESKey
        if is_session_crypt:
            if isinstance(session_aes_secret, str):
                session_aes_secret = __key_loader__(session_aes_secret)
            assert session_aes_secret is not None
            self._code_session_key = Fernet(session_aes_secret)

    def __encode_session_id__(self, data: str) -> str:
        """Encode a session identifier."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session key encoding is not enabled.")
        return (
            f"{self._sk_mark_symbol}"
            f"{self._code_session_key.encrypt(data.encode()).decode()}"
        )

    def __decode_session_id__(self, data: str) -> str:
        """Decode a session identifier."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session key encoding is not enabled.")
        if not data.startswith(self._sk_mark_symbol):
            raise ValueError("Session key is not encoded or is invalid.")
        return self._code_session_key.decrypt(
            data[len(self._sk_mark_symbol) :].encode()
        ).decode()

    def __encode_session_id_if_needed__(self, data: str) -> str:
        """Encode a session identifier when encryption is enabled."""
        if not hasattr(self, "_code_session_key"):
            return data
        try:
            return self.__encode_session_id__(data)
        except ValueError as error:
            logger.error("Failed to encode session ID: %s", error)
            return data

    def __decode_session_id_if_needed__(self, data: str) -> str:
        """Decode an encrypted session identifier."""
        if not hasattr(self, "_code_session_key"):
            return data
        try:
            return self.__decode_session_id__(data)
        except ValueError as error:
            logger.error("Failed to decode session ID: %s", error)
            return data

    def __encode_session_data__(self, data: dict[str, Any]) -> str:
        """Serialize and encrypt session data."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session data encoding is not enabled.")
        serialized = self._serializer.dumps(data).decode("utf-8")
        return self.__encode_session_id__(serialized)

    def __decode_session_data__(self, data: str) -> dict[str, Any]:
        """Decrypt and deserialize session data."""
        if not hasattr(self, "_code_session_key"):
            raise AttributeError("Session key encoding is not enabled.")
        return self._serializer.loads(self.__decode_session_id__(data))

    @property
    def id(self) -> str:
        """Return a new session identifier."""
        return self._id()
