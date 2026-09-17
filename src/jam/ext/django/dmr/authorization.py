# -*- coding: utf-8 -*-

"""Django-native authorization helpers for DMR."""

from __future__ import annotations

from dataclasses import replace
from http import HTTPStatus
from typing import Any

from dmr.errors import ErrorType, format_error
from dmr.response import APIError

from jam.authz import AuthorizationContext, Principal
from jam.ext.django.context import authorization_context, principal_context


def request_principal(request: Any) -> Principal[Any]:
    """Return the Principal associated with this exact request."""
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


def authorize(
    request: Any,
    permission: str,
    *,
    resource: Any = None,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Raise a DMR-native 403 when Django's permission chain denies access."""
    principal = request_principal(request)
    current = authorization_context.get()
    if current is None or current.request is not request:
        context = AuthorizationContext(
            request=request,
            resource=resource,
            attributes=dict(attributes or {}),
        )
    else:
        merged = {**current.attributes, **(attributes or {})}
        context = replace(
            current,
            request=request,
            resource=resource,
            attributes=merged,
        )
    context_token = authorization_context.set(context)
    principal_token = principal_context.set(principal)
    try:
        allowed = request.user.has_perm(permission, resource)
    finally:
        principal_context.reset(principal_token)
        authorization_context.reset(context_token)
    if not allowed:
        raise APIError(
            format_error(
                "Permission denied.",
                error_type=ErrorType.security,
            ),
            status_code=HTTPStatus.FORBIDDEN,
        )
