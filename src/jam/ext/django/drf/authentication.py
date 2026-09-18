# -*- coding: utf-8 -*-

"""DRF authentication backed by the Django Jam adapter."""

from __future__ import annotations

from typing import Any

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from jam.authz import Principal
from jam.exceptions import JamConfigurationError
from jam.ext.django._auth import (
    InvalidBearerCredential,
    authenticate_bearer,
    get_bearer_credential,
)
from jam.ext.django.context import principal_context


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
            credential = get_bearer_credential(request)
        except InvalidBearerCredential as error:
            raise AuthenticationFailed(self._error_message) from error
        if credential is None:
            return None

        current = principal_context.get()
        # ``request.user`` is resolved by DRF through this authenticator.
        # Reading it here would recursively invoke ``authenticate``. Django
        # middleware, when installed, has already populated the underlying
        # request user that we need to validate context reuse.
        user = getattr(request._request, "user", None)
        if (
            current is not None
            and current.subject == user
            and current.token_type in {"jwt", "jwe", "paseto"}
        ):
            return current.subject, current

        try:
            principal = authenticate_bearer(request)
        except JamConfigurationError:
            raise
        except InvalidBearerCredential as error:
            raise AuthenticationFailed(self._error_message) from error
        if principal is None:
            return None
        return principal.subject, principal

    def authenticate_header(self, request: Any) -> str:
        """Advertise the Bearer scheme for unauthenticated DRF responses."""
        return self.keyword
