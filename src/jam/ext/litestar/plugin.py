# -*- coding: utf-8 -*-

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from anyio import to_thread
from litestar.config.app import AppConfig
from litestar.connection import ASGIConnection
from litestar.di import Provide
from litestar.exceptions import (
    NotAuthorizedException,
    PermissionDeniedException,
)
from litestar.middleware import (
    AbstractAuthenticationMiddleware,
    AuthenticationResult,
    DefineMiddleware,
)
from litestar.plugins import InitPlugin

from jam import Jam
from jam.authz import Principal
from jam.ext._base import DEFAULT_SOURCES, Authenticator, CredentialSource


class JamAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    """Litestar authentication middleware configured per application."""

    def __init__(
        self,
        app: Any,
        *,
        jam: Jam,
        sources: Sequence[CredentialSource] = DEFAULT_SOURCES,
        via: str | None = None,
        reject_invalid: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize middleware for one application instance."""
        self.jam = jam
        self.authenticator = Authenticator(jam, sources=sources, via=via)
        self.reject_invalid = reject_invalid
        super().__init__(app, **kwargs)

    async def authenticate_request(
        self,
        connection: ASGIConnection,
    ) -> AuthenticationResult:
        """Authenticate a request and expose its principal as ``user``."""
        result = await to_thread.run_sync(
            lambda: self.authenticator.authenticate_request(
                headers=dict(connection.headers),
                cookies=dict(connection.cookies),
                query=dict(connection.query_params),
            )
        )
        connection.state.jam = self.jam
        connection.state.principal = result.principal
        connection.state.authentication = result
        if result.error is not None and self.reject_invalid:
            raise NotAuthorizedException("Invalid authentication credential.")
        return AuthenticationResult(user=result.principal, auth=result)


class JamPlugin(InitPlugin):
    """Install Jam DI and optional authentication middleware in Litestar."""

    def __init__(
        self,
        jam: Jam,
        *,
        sources: Sequence[CredentialSource] = DEFAULT_SOURCES,
        via: str | None = None,
        middleware: bool = True,
        reject_invalid: bool = True,
        exclude: str | list[str] | None = None,
    ) -> None:
        """Configure Litestar integration for a Jam instance."""
        self.jam = jam
        self.sources = tuple(sources)
        self.via = via
        self.middleware = middleware
        self.reject_invalid = reject_invalid
        self.exclude = exclude

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Add Jam to dependency injection and configure authentication."""
        app_config.dependencies.setdefault(
            "jam",
            Provide(lambda: self.jam, sync_to_thread=False),
        )
        if self.middleware:
            app_config.middleware.append(
                DefineMiddleware(
                    JamAuthenticationMiddleware,
                    jam=self.jam,
                    sources=self.sources,
                    via=self.via,
                    reject_invalid=self.reject_invalid,
                    exclude=self.exclude,
                )
            )
        return app_config


def permission_guard(
    jam: Jam,
    permission: str,
    *,
    context: Callable[[ASGIConnection], Any] | None = None,
) -> Callable[[ASGIConnection, Any], None]:
    """Build a Litestar guard requiring one Jam permission."""

    def guard(connection: ASGIConnection, _: Any) -> None:
        principal: Principal[Any] | None = connection.user
        if principal is None:
            raise NotAuthorizedException("Authentication required.")
        if not jam.authorize(
            principal,
            permission,
            context(connection) if context is not None else None,
        ):
            raise PermissionDeniedException("Permission denied.")

    return guard
