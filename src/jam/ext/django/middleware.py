# -*- coding: utf-8 -*-

"""Django middleware for request context and Bearer authentication."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import inspect
from typing import Any

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse

from jam.authz import AuthorizationContext, Principal
from jam.exceptions import JamConfigurationError
from jam.ext.django._auth import (
    InvalidBearerCredential,
    authenticate_bearer,
)
from jam.ext.django.context import authorization_context, principal_context


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
        try:
            principal = authenticate_bearer(request)
        except JamConfigurationError:
            raise
        except InvalidBearerCredential:
            return None, self._unauthorized()
        if principal is None:
            return None, None
        user = principal.subject
        request.user = user

        async def auser() -> Any:
            return user

        request.auser = auser
        return principal, None

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
