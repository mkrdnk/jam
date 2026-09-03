# -*- coding: utf-8 -*-

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    BaseUser,
)
from starlette.requests import HTTPConnection

from jam import Jam
from jam.aio import AsyncJam
from jam.authz import Principal
from jam.ext._base import (
    DEFAULT_SOURCES,
    AsyncAuthenticator,
    CredentialSource,
    permissions_from,
)


class JamUser(BaseUser):
    """Starlette user exposing the complete Jam principal."""

    def __init__(self, principal: Principal[Any]) -> None:
        """Initialize a user from an authenticated principal."""
        self.principal = principal

    @property
    def is_authenticated(self) -> bool:
        """Always true for an instantiated authenticated user."""
        return True

    @property
    def display_name(self) -> str:
        """Return a useful display name without requiring a user model."""
        subject = self.principal.subject
        if isinstance(subject, dict):
            value = (
                subject.get("username")
                or subject.get("name")
                or subject.get("id")
            )
        else:
            value = (
                getattr(subject, "username", None)
                or getattr(subject, "name", None)
                or getattr(subject, "id", None)
            )
        return "" if value is None else str(value)


class JamAuthBackend(AuthenticationBackend):
    """Authenticate Starlette HTTP and WebSocket connections with Jam."""

    def __init__(
        self,
        jam: AsyncJam | Jam,
        *,
        sources: Sequence[CredentialSource] = DEFAULT_SOURCES,
        via: str | None = None,
        reject_invalid: bool = True,
    ) -> None:
        """Initialize the backend with one shared Jam instance."""
        self.jam = jam
        self.authenticator = AsyncAuthenticator(
            jam,
            sources=sources,
            via=via,
        )
        self.reject_invalid = reject_invalid

    async def authenticate(
        self,
        conn: HTTPConnection,
    ) -> tuple[AuthCredentials, BaseUser] | None:
        """Authenticate a connection using Starlette's native contract."""
        result = await self.authenticator.authenticate_request(
            headers=dict(conn.headers),
            cookies=dict(conn.cookies),
            query=dict(conn.query_params),
        )
        conn.state.jam = self.jam
        conn.state.principal = result.principal
        conn.state.authentication = result
        if result.error is not None:
            if self.reject_invalid:
                raise AuthenticationError("Invalid authentication credential.")
            return None
        if result.principal is None:
            return None
        scopes = ["authenticated", *permissions_from(result.principal)]
        return AuthCredentials(scopes), JamUser(result.principal)
