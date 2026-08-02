# -*- coding: utf-8 -*-

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
import os
from typing import Any
from uuid import uuid4


try:
    import tinydb
except ImportError:
    raise ImportError(
        "JSON module is not installed. Please install it with 'pip install jamlib[json]'."
    )

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import JamSessionNotFound
from jam.logger import BaseLogger
from jam.sessions.__base__ import BaseSessionModule


class JSONSessions(BaseSessionModule):
    """Session management module for JSON storage."""

    _SESSION_TYPE = "json"

    def __init__(
        self,
        session_type: str | None = None,
        sessions_type: str | None = None,
        json_path: str = "sessions.json",
        is_session_crypt: bool = False,
        session_aes_secret: bytes | str | None = os.getenv(
            "JAM_SESSION_AES_SECRET", None
        ),
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        logger: BaseLogger | None = None,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize the JSON session management module.

        Args:
            session_type (str | None): Session type for validation.
            sessions_type (str | None): Deprecated alias for session_type.
            json_path (str): Path to the JSON file where sessions will be stored.
            is_session_crypt (bool): If True, session keys will be encoded.
            session_aes_secret (Optional[bytes]): AES secret for encoding session keys. Required if `is_session_crypt` is True.
            id_factory (Callable[[], str], optional): A callable that generates unique IDs. Defaults to a UUID factory.
            serializer (Union[BaseEncoder, type[BaseEncoder]], optional): JSON encoder/decoder. Defaults to JsonEncoder.
            logger (Optional[BaseLogger], optional): Logger instance. Defaults to None.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.session".

        Raises:
            JamSessionEmptyAESKey: If 'is_session_crypt' is True and 'session_aes_secret' is not provided.
            ValueError: If the session type does not match the module type.
        """
        self._resolve_session_type(session_type, sessions_type)
        super().__init__(
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            id_factory=id_factory,
            serializer=serializer,
            logger=logger,
        )
        self._db = tinydb.TinyDB(json_path)
        self._qs = tinydb.Query()
        if self._logger:
            self._logger.debug("JSON database initialized at %s", json_path)

    @dataclass
    class _SessionDoc:
        key: str
        session_id: str
        data: str
        created_at: float = field(default_factory=datetime.now().timestamp)

    def create(self, session_key: str, data: dict) -> str:
        """Create a new session.

        Args:
            session_key (str): The session key.
            data (dict): The data to be stored in the session.

        Returns:
            str: The ID of the created session.
        """
        session_id = self.__encode_session_id_if_needed__(self.id)

        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        doc = self._SessionDoc(
            key=session_key,
            session_id=session_id,
            data=dumps_data,
        )

        self._db.insert(doc.__dict__)
        if self._logger:
            self._logger.debug("Session created with ID %s", session_id)
        return session_id

    def get(self, session_id) -> dict | None:
        """Retrieve session data by session ID.

        Args:
            session_id (str): The ID of the session to retrieve.

        Returns:
            dict | None: The session data if found, otherwise None.
        """
        if self._logger:
            self._logger.debug(f"Getting session with ID: {session_id}")
        # session_id = self.__decode_session_id_if_needed__(session_id)
        result = self._db.search(self._qs.session_id == session_id)
        if result:
            try:
                loads_data = self.__decode_session_data__(result[0]["data"])
            except AttributeError:
                loads_data = self._serializer.loads(result[0]["data"])
            if self._logger:
                self._logger.debug(
                    f"Session {session_id} found, data keys: {list(loads_data.keys()) if isinstance(loads_data, dict) else 'N/A'}"
                )
            del result
            return loads_data
        if self._logger:
            self._logger.debug(f"Session {session_id} not found")
        return None

    def delete(self, session_id: str) -> None:
        """Delete a session by its ID.

        Args:
            session_id (str): The ID of the session to delete.

        Returns:
            None
        """
        if self._logger:
            self._logger.debug(f"Deleting session with ID: {session_id}")
        removed_count = self._db.remove(self._qs.session_id == session_id)
        if self._logger:
            self._logger.debug(
                f"Session with ID {session_id} deleted, removed {len(removed_count)} document(s)"
            )

    def update(self, session_id: str, data: dict) -> None:
        """Update session data by its ID.

        Args:
            session_id (str): The ID of the session to update.
            data (dict): The new data to store in the session.

        Raises:
            JamSessionNotFound: If session not found
        """
        if self._logger:
            self._logger.debug(
                f"Updating session {session_id} with data keys: {list(data.keys())}"
            )
        try:
            dumps_data = self.__encode_session_data__(data)
        except AttributeError:
            dumps_data = self._serializer.dumps(data).decode("utf-8")
        del data

        if not self._db.search(self._qs.session_id == session_id):
            raise JamSessionNotFound(details={"session_id": session_id})

        updated_count = self._db.update(
            {"data": dumps_data}, self._qs.session_id == session_id
        )
        if self._logger:
            self._logger.debug(
                f"Session with ID {session_id} updated, modified {len(updated_count)} document(s)"
            )

    def clear(self, session_key: str) -> None:
        """Clear all sessions for a given session key.

        Args:
            session_key (str): The session key to clear.

        Returns:
            None
        """
        self._db.remove(self._qs.key == session_key)

    def rework(self, session_id: str) -> str:
        """Rework (regenerate) a session ID.

        Args:
            session_id (str): The current session ID to be reworked.

        Raises:
            JamSessionNotFound: If session not found

        Returns:
            str: The new session ID.
        """
        result = self._db.search(self._qs.session_id == session_id)
        if not result:
            raise JamSessionNotFound(details={"session_id": session_id})

        new_session_id = self.__encode_session_id_if_needed__(self.id)
        self._db.update(
            {"session_id": new_session_id},
            self._qs.session_id == session_id,
        )
        if self._logger:
            self._logger.debug(
                "Session ID %s reworked to %s", session_id, new_session_id
            )
        return new_session_id
