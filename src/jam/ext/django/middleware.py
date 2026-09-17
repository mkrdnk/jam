# -*- coding: utf-8 -*-

"""Django middleware for request context and Bearer authentication."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Awaitable, Callable
import inspect
import json
import re
from typing import Any

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import (
    ImproperlyConfigured,
    ObjectDoesNotExist,
    ValidationError,
)
from django.http import HttpRequest, HttpResponse

from jam.authz import AuthorizationContext, Principal
from jam.exceptions import JamConfigurationError, JamError
from jam.ext._base import DEFAULT_SOURCES, _extract_credential
from jam.ext.django.context import authorization_context, principal_context
from jam.ext.django.runtime import get_jam


_PASETO_PREFIX = re.compile(r"^v[1-4]\.(?:local|public)\.")


def _bearer_credential(request: HttpRequest) -> str | None:
    """Extract an explicitly supplied Bearer credential, if it is well formed."""
    value = request.headers.get("Authorization")
    if value is None:
        return None
    scheme, separator, credential = value.partition(" ")
    if scheme.casefold() != "bearer":
        return None
    if not separator or not credential.strip():
        return ""
    token, _source = _extract_credential(
        DEFAULT_SOURCES,
        headers=request.headers,
        cookies={},
        query=None,
    )
    return token or ""


def _token_type(token: str) -> str | None:
    """Classify JWT and PASETO without trying cryptographic verification."""
    if _PASETO_PREFIX.match(token):
        return "paseto"
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        encoded = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(encoded))
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None
    return "jwt" if isinstance(header, dict) and "alg" in header else None


def _token_subject(principal: Principal[Any]) -> Any:
    """Return the primary-key subject from Jam's standard payload shape."""
    subject = principal.subject
    if isinstance(subject, dict):
        return subject.get("id", subject.get("sub"))
    return getattr(subject, "id", getattr(subject, "sub", subject))


class JamMiddleware:
    """Bridge Django requests to Jam without replacing session authentication."""

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Callable[..., Any]) -> None:
        """Validate ordering and select the matching sync or async wrapper."""
        self._validate_order()
        self.get_response = get_response
        self._is_async = inspect.iscoroutinefunction(get_response)

    def __call__(
        self,
        request: HttpRequest,
    ) -> HttpResponse | Awaitable[HttpResponse]:
        """Dispatch through Django's sync or async middleware contract."""
        if self._is_async:
            return self._async_call(request)
        return self._sync_call(request)

    def _validate_order(self) -> None:
        middleware = list(getattr(settings, "MIDDLEWARE", ()))
        own_paths = (
            "jam.ext.django.JamMiddleware",
            "jam.ext.django.middleware.JamMiddleware",
        )
        required = (
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        )
        try:
            own_index = min(
                middleware.index(path)
                for path in own_paths
                if path in middleware
            )
            indices = [middleware.index(item) for item in required]
        except ValueError as error:
            raise ImproperlyConfigured(
                "JamMiddleware must follow SessionMiddleware and "
                "AuthenticationMiddleware."
            ) from error
        if any(index > own_index for index in indices):
            raise ImproperlyConfigured(
                "JamMiddleware must be placed after SessionMiddleware and "
                "AuthenticationMiddleware."
            )

    @staticmethod
    def _unauthorized() -> HttpResponse:
        """Build the intentionally non-specific Bearer authentication failure."""
        return HttpResponse(
            "Invalid Bearer credential.",
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _authenticate_bearer(
        self,
        request: HttpRequest,
    ) -> tuple[Principal[Any] | None, HttpResponse | None]:
        """Authenticate a token and resolve its subject to Django's user model."""
        credential = _bearer_credential(request)
        if credential is None:
            return None, None
        via = _token_type(credential)
        if via is None:
            return None, self._unauthorized()
        try:
            token_principal = get_jam().authenticate(credential, via=via)
            user = get_user_model()._default_manager.get(
                pk=_token_subject(token_principal)
            )
        except JamConfigurationError:
            raise
        except (
            JamError,
            ObjectDoesNotExist,
            OverflowError,
            TypeError,
            ValidationError,
            ValueError,
        ):
            return None, self._unauthorized()

        request.user = user

        async def auser() -> Any:
            return user

        request.auser = auser
        return (
            Principal(
                subject=user,
                claims=token_principal.claims,
                token_type=token_principal.token_type,
            ),
            None,
        )

    @staticmethod
    def _set_context(
        request: HttpRequest,
        principal: Principal[Any],
    ) -> tuple[Any, Any]:
        """Set request-local state after authentication has completed."""
        context_token = authorization_context.set(
            AuthorizationContext(request=request)
        )
        principal_token = principal_context.set(principal)
        return context_token, principal_token

    def _enter(
        self,
        request: HttpRequest,
    ) -> tuple[Any, Any, HttpResponse | None]:
        """Set request-local state and optionally authenticate a Bearer token."""
        principal, response = self._authenticate_bearer(request)
        if response is not None:
            return None, None, response
        if principal is None:
            principal = Principal(
                subject=request.user,
                claims={},
                token_type="django",
            )
        context_token, principal_token = self._set_context(request, principal)
        return context_token, principal_token, None

    def _sync_call(self, request: HttpRequest) -> HttpResponse:
        """Process a synchronous request while isolating ContextVars."""
        context_token, principal_token, response = self._enter(request)
        if response is not None:
            return response
        try:
            return self.get_response(request)
        finally:
            authorization_context.reset(context_token)
            principal_context.reset(principal_token)

    async def _async_call(self, request: HttpRequest) -> HttpResponse:
        """Process an asynchronous request without using sync ORM in its loop."""
        principal, response = await sync_to_async(
            self._authenticate_bearer,
            thread_sensitive=True,
        )(request)
        if response is not None:
            return response
        if principal is None:
            principal = Principal(
                subject=request.user,
                claims={},
                token_type="django",
            )
        context_token, principal_token = self._set_context(request, principal)
        try:
            result = self.get_response(request)
            if isinstance(result, Awaitable):
                return await result
            return result
        finally:
            authorization_context.reset(context_token)
            principal_context.reset(principal_token)
