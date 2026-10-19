"""Serialized, thread-adapted JSON session storage."""

import asyncio
from collections.abc import Callable
from threading import Lock
from typing import Any, TypeVar
from uuid import uuid4

from jam.aio.sessions.__base__ import BaseAsyncSessionModule
from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamError
from jam.sessions.json import JSONSessions as SyncJSONSessions


_ResultT = TypeVar("_ResultT")


class JSONSessions(BaseAsyncSessionModule):
    """Async JSON sessions with exclusive access within one instance.

    Sharing the same file between instances or processes is unsupported.
    Cancellation does not interrupt a worker that has already started.
    """

    def __init__(
        self,
        json_path: str = "sessions.json",
        is_session_crypt: bool = False,
        session_aes_secret: bytes | None = None,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
    ) -> None:
        """Initialize storage and its worker-side lock.

        Args:
            json_path: Storage file, exclusively owned by this instance.
            is_session_crypt: Whether to encrypt identifiers and payloads.
            session_aes_secret: Fernet encryption key.
            id_factory: Factory for fresh session identifiers.
            serializer: Payload serializer.
        """
        super().__init__(
            id_factory=id_factory,
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            serializer=serializer,
        )
        self._session = SyncJSONSessions(
            json_path=json_path,
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            id_factory=id_factory,
            serializer=serializer,
        )
        self._lock = Lock()
        self._closed = False

    def _locked(
        self, operation: Callable[..., _ResultT], *args: Any
    ) -> _ResultT:
        """Run a whole storage operation while holding the worker lock."""
        with self._lock:
            if self._closed:
                raise JamError(
                    message="JSON session storage is closed.",
                    error_code="sessions.closed",
                )
            return operation(*args)

    async def create(self, session_key: str, data: dict[str, Any]) -> str:
        """Create a session without blocking the event loop."""
        return await asyncio.to_thread(
            self._locked, self._session.create, session_key, data
        )

    async def get(self, session_id: str) -> dict[str, Any] | None:
        """Read a session, or return None when it does not exist."""
        return await asyncio.to_thread(
            self._locked, self._session.get, session_id
        )

    async def delete(self, session_id: str) -> None:
        """Delete a session under the same lock as updates and rotation."""
        await asyncio.to_thread(self._locked, self._session.delete, session_id)

    async def update(self, session_id: str, data: dict[str, Any]) -> None:
        """Update an existing session as one worker operation."""
        await asyncio.to_thread(
            self._locked, self._session.update, session_id, data
        )

    async def clear(self, session_key: str) -> None:
        """Delete all sessions in the specified namespace."""
        await asyncio.to_thread(self._locked, self._session.clear, session_key)

    async def rework(self, session_id: str) -> str:
        """Rotate an existing session identifier under the storage lock."""
        return await asyncio.to_thread(
            self._locked, self._session.rework, session_id
        )

    def _close(self) -> None:
        """Wait for any running operation and close storage once."""
        with self._lock:
            if not self._closed:
                self._session.close()
                self._closed = True

    async def aclose(self) -> None:
        """Close storage without blocking the event loop."""
        await asyncio.to_thread(self._close)
