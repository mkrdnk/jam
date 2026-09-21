# -*- coding: utf-8 -*-

"""Django Modern REST authentication backed by Jam."""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Literal

from django.core.exceptions import ImproperlyConfigured
from django.middleware.csrf import CsrfViewMiddleware
from django.views.decorators.debug import sensitive_variables
from dmr.exceptions import NotAuthenticatedError  # type: ignore[missing-import]
from dmr.metadata import (  # type: ignore[missing-import]
    EndpointMetadata,
    ResponseSpec,
)
from dmr.openapi.objects import (  # type: ignore[missing-import]
    SecurityRequirement,
    SecurityScheme,
)
from dmr.response import APIError  # type: ignore[missing-import]
from dmr.security import AsyncAuth, SyncAuth  # type: ignore[missing-import]

from jam.ext import CredentialSource
from jam.ext.django._authentication import (
    InvalidCredential,
    authenticate_request,
    authenticate_request_async,
    configured_mechanisms,
    install_principal,
)


if TYPE_CHECKING:
    # DMR is available only on Python 3.11+, while Jam supports Python 3.10.
    from dmr.controller import Controller  # type: ignore[missing-import]
    from dmr.endpoint import Endpoint  # type: ignore[missing-import]
    from dmr.serializer import BaseSerializer  # type: ignore[missing-import]


_Mode = Literal["all", "bearer", "session"]
_BEARER_TYPES = frozenset({"jwt", "jwe", "paseto"})


def _bearer_format() -> str | None:
    enabled = configured_mechanisms()
    formats = [
        label
        for name, label in (
            ("jwt", "JWT"),
            ("jwe", "JWE"),
            ("paseto", "PASETO"),
            ("macaroon", "Macaroon"),
        )
        if name in enabled
    ]
    if len(formats) > 1:
        return ", ".join(formats[:-1]) + " or " + formats[-1]
    return formats[0] if formats else None


def _api_key_scheme(source: CredentialSource) -> SecurityScheme:
    description = "Jam Session authentication"
    if source.kind == "header" and source.scheme is not None:
        description += f"; value must use the {source.scheme} prefix"
    return SecurityScheme(
        type="apiKey",
        name=source.name,
        security_scheme_in=source.kind,
        description=description,
    )


def _ensure_csrf(controller: Controller[BaseSerializer]) -> None:
    """Raise a native DMR 403 when Django rejects the CSRF check."""
    middleware = CsrfViewMiddleware(lambda request: None)
    rejection = middleware.process_view(
        controller.request,
        lambda request: None,
        (),
        {},
    )
    if rejection is not None:
        raise APIError(
            controller.format_error("CSRF verification failed."),
            status_code=HTTPStatus.FORBIDDEN,
        )


class _JamAuth:
    """Immutable configuration shared by sync and async DMR adapters."""

    __slots__ = ("_mode", "_session_source")

    def __init__(
        self,
        *,
        source: Literal["all", "bearer", "session"] | CredentialSource = "all",
        session_source: CredentialSource = CredentialSource.cookie("session"),
    ) -> None:
        if isinstance(source, CredentialSource):
            self._mode: _Mode = "session"
            self._session_source = source
        elif source in {"all", "bearer", "session"}:
            self._mode = source
            self._session_source = session_source
        else:
            raise ValueError(
                "source must be 'all', 'bearer', 'session', or a "
                "CredentialSource."
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
        if not names:
            raise ImproperlyConfigured(
                "No enabled Jam authentication mechanism is accepted by "
                "this auth instance."
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

    def _uses_cookie_session(self) -> bool:
        return self._accepts_session and self._session_source.kind == "cookie"

    def _ensure_cookie_session_csrf(
        self,
        controller: Controller[BaseSerializer],
        principal: Any,
    ) -> None:
        if (
            self._uses_cookie_session()
            and principal.token_type == "session"
            and controller.request.COOKIES.get(self._session_source.name)
        ):
            _ensure_csrf(controller)

    def _add_csrf_response_spec(
        self,
        controller_cls: type[Controller[BaseSerializer]],
        existing_responses: Mapping[HTTPStatus, ResponseSpec],
        responses: list[ResponseSpec],
    ) -> list[ResponseSpec]:
        """Add the cookie-session CSRF response unless already documented."""
        if (
            not self._uses_cookie_session()
            or HTTPStatus.FORBIDDEN in existing_responses
        ):
            return responses
        return [
            *responses,
            ResponseSpec(
                controller_cls.error_model,
                status_code=HTTPStatus.FORBIDDEN,
                description="Raised when CSRF check failed",
            ),
        ]


class JamSyncAuth(_JamAuth, SyncAuth):
    """Authenticate Jam credentials for synchronous DMR controllers."""

    __slots__ = ()

    def provide_response_specs(
        self,
        metadata: EndpointMetadata,
        controller_cls: type[Controller[BaseSerializer]],
        existing_responses: Mapping[HTTPStatus, ResponseSpec],
    ) -> list[ResponseSpec]:
        """Document authentication and cookie-session CSRF failures."""
        return self._add_csrf_response_spec(
            controller_cls,
            existing_responses,
            super().provide_response_specs(
                metadata,
                controller_cls,
                existing_responses,
            ),
        )

    @sensitive_variables()
    def __call__(
        self,
        endpoint: Endpoint,
        controller: Controller[BaseSerializer],
    ) -> JamSyncAuth | None:
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
        self._ensure_cookie_session_csrf(controller, principal)
        install_principal(controller.request, principal)
        return self


class JamAsyncAuth(_JamAuth, AsyncAuth):
    """Authenticate Jam credentials for asynchronous DMR controllers."""

    __slots__ = ()

    def provide_response_specs(
        self,
        metadata: EndpointMetadata,
        controller_cls: type[Controller[BaseSerializer]],
        existing_responses: Mapping[HTTPStatus, ResponseSpec],
    ) -> list[ResponseSpec]:
        """Document authentication and cookie-session CSRF failures."""
        return self._add_csrf_response_spec(
            controller_cls,
            existing_responses,
            super().provide_response_specs(
                metadata,
                controller_cls,
                existing_responses,
            ),
        )

    @sensitive_variables()
    async def __call__(
        self,
        endpoint: Endpoint,
        controller: Controller[BaseSerializer],
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
        self._ensure_cookie_session_csrf(controller, principal)
        install_principal(controller.request, principal)
        return self
