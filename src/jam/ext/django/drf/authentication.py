# -*- coding: utf-8 -*-

"""DRF authentication backed by the Django Jam adapter."""

from __future__ import annotations

from typing import Any

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from jam.authz import Principal
from jam.ext.django._authentication import (
    InvalidCredential,
    authenticate_request,
)


class JamAuthentication(BaseAuthentication):
    """Authenticate Bearer JWT, compact JWE, and PASETO credentials with Jam."""

    keyword = "Bearer"
    _error_message = "Invalid Bearer credential."

    def authenticate(
        self,
        request: Any,
    ) -> tuple[Any, Principal[Any]] | None:
        """Return the Django user and its Jam principal for a Bearer token."""
        try:
            principal = authenticate_request(
                request._request,
                session_source=None,
            )
        except InvalidCredential as error:
            raise AuthenticationFailed(self._error_message) from error
        if principal is None:
            return None
        return principal.subject, principal

    # DRF's base implementation returns None, but its documented extension
    # contract allows authentication classes to return an HTTP scheme.
    def authenticate_header(  # type: ignore[bad-override]
        self,
        request: Any,
    ) -> str:
        """Advertise the Bearer scheme for unauthenticated DRF responses."""
        return self.keyword
