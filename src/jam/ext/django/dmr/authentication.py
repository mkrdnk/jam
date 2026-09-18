# -*- coding: utf-8 -*-

"""Django Modern REST authentication backed by Jam."""

from __future__ import annotations

from typing import Any, Literal

from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables
from dmr.exceptions import NotAuthenticatedError
from dmr.openapi.objects import SecurityRequirement, SecurityScheme
from dmr.security import AsyncAuth, SyncAuth

from jam.ext import CredentialSource
from jam.ext.django._authentication import (
    InvalidCredential,
    authenticate_request,
    authenticate_request_async,
    configured_mechanisms,
    install_principal,
)


_Mode = Literal["all", "bearer", "session"]
_BEARER_TYPES = frozenset({"jwt", "jwe", "paseto"})


def _bearer_format() -> str | None:
    enabled = configured_mechanisms()
    match (
        "jwt" in enabled,
        "jwe" in enabled,
        "paseto" in enabled,
    ):
        case (True, False, False):
            return "JWT"
        case (False, True, False):
            return "JWE"
        case (False, False, True):
            return "PASETO"
        case (True, True, False):
            return "JWT or JWE"
        case (True, False, True):
            return "JWT or PASETO"
        case (False, True, True):
            return "JWE or PASETO"
        case (True, True, True):
            return "JWT, JWE or PASETO"
        case _:
            return None


def _api_key_scheme(source: CredentialSource) -> SecurityScheme:
    return SecurityScheme(
        type="apiKey",
        name=source.name,
        security_scheme_in=source.kind,
        description="Jam Session authentication",
    )


class _JamAuth:
    """Immutable configuration shared by sync and async DMR adapters."""

    __slots__ = ("_mode", "_session_source")

    def __init__(
        self,
        *,
        source: Literal["all", "bearer"] | CredentialSource = "all",
        session_source: CredentialSource = CredentialSource.cookie("session"),
    ) -> None:
        if isinstance(source, CredentialSource):
            self._mode: _Mode = "session"
            self._session_source = source
        elif source in {"all", "bearer"}:
            self._mode = source
            self._session_source = session_source
        else:
            raise ValueError(
                "source must be 'all', 'bearer', or a CredentialSource."
            )

    @property
    def _accepts_bearer(self) -> bool:
        return self._mode in {"all", "bearer"}

    @property
    def _accepts_session(self) -> bool:
        return self._mode in {"all", "session"}

    @property
    def security_schemes(self) -> dict[str, SecurityScheme]:
        """Describe mechanisms enabled by the normal Jam configuration."""
        enabled = configured_mechanisms()
        schemes: dict[str, SecurityScheme] = {}
        bearer_format = _bearer_format()
        if self._accepts_bearer and bearer_format is not None:
            schemes["jamBearer"] = SecurityScheme(
                type="http",
                scheme="bearer",
                bearer_format=bearer_format,
                description="Jam JWT, JWE, or PASETO authentication",
            )
        if self._accepts_session and "session" in enabled:
            schemes["jamSession"] = _api_key_scheme(self._session_source)
        return schemes

    @property
    def security_requirement(self) -> SecurityRequirement:
        """Return one requirement, as required by DMR's current API."""
        names = tuple(self.security_schemes)
        if len(names) > 1:
            raise ImproperlyConfigured(
                "DMR cannot express Bearer OR Jam Session from one auth "
                "instance. Configure separate source='bearer' and "
                "source=CredentialSource(...) instances."
            )
        return {name: [] for name in names}

    @property
    def www_authenticate_challenge(self) -> str | None:
        """Advertise only credentials carried by Authorization."""
        if self._accepts_bearer and configured_mechanisms() & _BEARER_TYPES:
            return "Bearer"
        return None

    def _options(self) -> dict[str, Any]:
        return {
            "bearer": self._accepts_bearer,
            "session_source": (
                self._session_source if self._accepts_session else None
            ),
        }


class JamSyncAuth(_JamAuth, SyncAuth):
    """Authenticate Jam credentials for synchronous DMR controllers."""

    __slots__ = ()

    @sensitive_variables()
    def __call__(self, endpoint: Any, controller: Any) -> JamSyncAuth | None:
        """Set DMR's canonical request identity after Jam authentication."""
        del endpoint
        try:
            principal = authenticate_request(
                controller.request,
                **self._options(),
            )
        except InvalidCredential:
            raise NotAuthenticatedError from None
        if principal is None:
            return None
        install_principal(controller.request, principal)
        return self


class JamAsyncAuth(_JamAuth, AsyncAuth):
    """Authenticate Jam credentials for asynchronous DMR controllers."""

    __slots__ = ()

    @sensitive_variables()
    async def __call__(
        self,
        endpoint: Any,
        controller: Any,
    ) -> JamAsyncAuth | None:
        """Set identity using async credential and Django ORM paths."""
        del endpoint
        try:
            principal = await authenticate_request_async(
                controller.request,
                **self._options(),
            )
        except InvalidCredential:
            raise NotAuthenticatedError from None
        if principal is None:
            return None
        install_principal(controller.request, principal)
        return self
