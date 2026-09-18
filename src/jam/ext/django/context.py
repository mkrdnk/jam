# -*- coding: utf-8 -*-

"""Request-local state shared by the middleware and auth backend."""

from contextvars import ContextVar
from dataclasses import replace
from typing import Any

from jam.authz import AuthorizationContext, Principal


authorization_context: ContextVar[AuthorizationContext | None] = ContextVar(
    "jam_django_authorization_context",
    default=None,
)
principal_context: ContextVar[Principal[Any] | None] = ContextVar(
    "jam_django_principal",
    default=None,
)


def context_for(resource: Any = None) -> AuthorizationContext:
    """Build a context without mutating the request-local context."""
    current = authorization_context.get()
    if current is None:
        return AuthorizationContext(resource=resource)
    return replace(current, resource=resource)
