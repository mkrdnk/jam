# -*- coding: utf-8 -*-

"""Django middleware for request context and Jam credential authentication."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
import inspect
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse

from jam.authz import AuthorizationContext, Principal
from jam.exceptions import JamConfigurationError
from jam.ext.django._authentication import (
    InvalidCredential,
    authenticate_request,
    authenticate_request_async,
    configured_mechanisms,
    install_principal,
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
        """Build an intentionally non-specific authentication failure."""
        headers = (
            {"WWW-Authenticate": "Bearer"}
            if configured_mechanisms() & {"jwt", "jwe", "paseto"}
            else None
        )
        return HttpResponse(
            "Invalid Jam credential.",
            status=401,
            headers=headers,
        )

    def _authenticate(
        self,
        request: HttpRequest,
    ) -> tuple[Principal[Any] | None, HttpResponse | None]:
        """Authenticate Jam credentials and resolve their Django user."""
        try:
            principal = authenticate_request(request)
        except JamConfigurationError:
            raise
        except InvalidCredential:
            return None, self._unauthorized()
        if principal is None:
            return None, None
        install_principal(request, principal)
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
        """Set request-local state and optionally authenticate Jam credentials."""
        principal, response = self._authenticate(request)
        if response is not None:
            return None, None, response
        if principal is None:
            principal = Principal(
                subject=getattr(request, "user"),
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
        try:
            principal = await authenticate_request_async(request)
        except JamConfigurationError:
            raise
        except InvalidCredential:
            return self._unauthorized()
        if principal is not None:
            install_principal(request, principal)
        if principal is None:
            auser = getattr(request, "auser", None)
            user = (
                await auser()
                if auser is not None
                else getattr(request, "user")
            )
            principal = Principal(
                subject=user,
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
