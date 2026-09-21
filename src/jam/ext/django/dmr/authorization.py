# -*- coding: utf-8 -*-

"""Django-native authorization helpers for DMR."""

from __future__ import annotations

from dataclasses import replace
from http import HTTPStatus
from typing import Any

from dmr.errors import ErrorType, format_error  # type: ignore[missing-import]
from dmr.response import APIError  # type: ignore[missing-import]
from dmr.security import (  # type: ignore[missing-import]
    AuthenticatedHttpRequest,
)

from jam.authz import AuthorizationContext, Principal
from jam.ext.django.context import authorization_context, principal_context


_UNSET = object()


def request_principal(
    request: AuthenticatedHttpRequest[Any],
) -> Principal[Any]:
    """Return this request's Principal, including an anonymous Django user.

    A request not authenticated by Jam falls back to a Principal with
    ``token_type="django"``. Its subject can be ``AnonymousUser``; callers
    must inspect ``principal.subject.is_authenticated`` when that matters.
    """
    principal = getattr(request, "_jam_principal", None)
    if isinstance(principal, Principal):
        return principal
    context = authorization_context.get()
    current = principal_context.get()
    if (
        context is not None
        and context.request is request
        and current is not None
    ):
        return current
    user = request.user
    return Principal(subject=user, claims={}, token_type="django")


def _context_for(
    request: AuthenticatedHttpRequest[Any],
    resource: Any,
    attributes: dict[str, Any] | None,
) -> AuthorizationContext:
    current = authorization_context.get()
    if current is None or current.request is not request:
        return AuthorizationContext(
            request=request,
            resource=None if resource is _UNSET else resource,
            attributes=dict(attributes or {}),
        )
    merged = {**current.attributes, **(attributes or {})}
    return replace(
        current,
        request=request,
        resource=current.resource if resource is _UNSET else resource,
        attributes=merged,
    )


def _raise_permission_denied() -> None:
    raise APIError(
        format_error(
            "Permission denied.",
            error_type=ErrorType.security,
        ),
        status_code=HTTPStatus.FORBIDDEN,
    )


def authorize(
    request: AuthenticatedHttpRequest[Any],
    permission: str,
    *,
    resource: Any = _UNSET,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Synchronously enforce a Django permission with a DMR-native 403.

    An omitted ``resource`` inherits the resource from an existing
    authorization context for this request. Pass ``None`` explicitly to
    clear it.
    """
    principal = request_principal(request)
    context = _context_for(request, resource, attributes)
    context_token = authorization_context.set(context)
    principal_token = principal_context.set(principal)
    try:
        allowed = request.user.has_perm(permission, context.resource)
    finally:
        principal_context.reset(principal_token)
        authorization_context.reset(context_token)
    if not allowed:
        _raise_permission_denied()


async def aauthorize(
    request: AuthenticatedHttpRequest[Any],
    permission: str,
    *,
    resource: Any = _UNSET,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Asynchronously enforce a Django permission with a DMR-native 403.

    An omitted ``resource`` inherits the resource from an existing
    authorization context for this request. Pass ``None`` explicitly to
    clear it.
    """
    principal = request_principal(request)
    context = _context_for(request, resource, attributes)
    context_token = authorization_context.set(context)
    principal_token = principal_context.set(principal)
    try:
        allowed = await request.user.ahas_perm(
            permission,
            context.resource,
        )
    finally:
        principal_context.reset(principal_token)
        authorization_context.reset(context_token)
    if not allowed:
        _raise_permission_denied()
