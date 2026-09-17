# -*- coding: utf-8 -*-

"""Shared authentication primitives for Django integrations."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Literal

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import (
    ImproperlyConfigured,
    ObjectDoesNotExist,
    ValidationError,
)
from django.views.decorators.debug import sensitive_variables

from jam.__core__ import JamAuthType
from jam.authz import Principal
from jam.exceptions import JamConfigurationError, JamError
from jam.ext import CredentialSource
from jam.ext.django.runtime import get_async_jam, get_jam


BearerType = Literal["jwt", "jwe", "paseto"]
_PASETO_PREFIX = re.compile(r"^v[1-4]\.(?:local|public)\.")
_AUTHENTICATED_TYPES = frozenset({"jwt", "jwe", "paseto", "session"})


class InvalidCredential(Exception):
    """Raised when an explicitly supplied Jam credential is invalid."""


def configured_mechanisms() -> frozenset[str]:
    """Return credential mechanisms enabled by ``JAM_CONFIG``."""
    if not hasattr(settings, "JAM_CONFIG"):
        raise ImproperlyConfigured(
            "JAM_CONFIG must be defined to use the Jam Django integration."
        )
    config: Any = settings.JAM_CONFIG
    if not isinstance(config, dict):
        raise ImproperlyConfigured(
            "JAM_CONFIG must be a Jam configuration dict."
        )
    jose = config.get("jose", {})
    jwt = jose.get("jwt")
    mechanisms = {
        name
        for name, value in (
            ("jwt", jwt),
            ("paseto", config.get("paseto")),
            ("session", config.get("session")),
        )
        if value is not None
    }
    if isinstance(jwt, dict) and jwt.get("enc") is not None:
        mechanisms.add("jwe")
    return frozenset(mechanisms)


@sensitive_variables()
def detect_bearer_type(credential: str) -> BearerType | None:
    """Classify a compact Jam Bearer credential before verification."""
    if _PASETO_PREFIX.match(credential):
        return "paseto"
    parts = credential.split(".")
    if len(parts) not in {3, 5}:
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
    if not isinstance(header, dict):
        return None
    if len(parts) == 5 and "enc" in header:
        return "jwe"
    if len(parts) == 3 and "alg" in header:
        return "jwt"
    return None


@sensitive_variables()
def bearer_credential(request: Any) -> str | None:
    """Extract an HTTP Bearer credential, rejecting malformed Bearer input."""
    value = request.headers.get("Authorization")
    if value is None:
        return None
    scheme, separator, credential = value.partition(" ")
    if scheme.casefold() != "bearer":
        return None
    credential = credential.strip()
    if not separator or not credential:
        raise InvalidCredential
    return credential


@sensitive_variables()
def source_credential(
    request: Any,
    source: CredentialSource,
) -> str | None:
    """Extract one configured source and distinguish absent from malformed."""
    if source.kind == "header":
        value = request.headers.get(source.name)
    elif source.kind == "cookie":
        value = request.COOKIES.get(source.name)
    else:
        value = request.GET.get(source.name)
    if value is None or value == "":
        return None
    if source.scheme is None:
        return value
    scheme, separator, credential = value.partition(" ")
    credential = credential.strip()
    if (
        not separator
        or scheme.casefold() != source.scheme.casefold()
        or not credential
    ):
        raise InvalidCredential
    return credential


def _subject_pk(principal: Principal[Any]) -> Any:
    """Extract the Django primary key from Jam's standard subject shapes."""
    subject = principal.subject
    if isinstance(subject, dict):
        return subject.get("id", subject.get("sub"))
    return getattr(subject, "id", getattr(subject, "sub", subject))


def adapt_principal(
    principal: Principal[Any],
    user: Any,
) -> Principal[Any]:
    """Preserve all credential claims while replacing the subject."""
    return Principal(
        subject=user,
        claims=principal.claims,
        token_type=principal.token_type,
    )


def _invalid_errors() -> tuple[type[BaseException], ...]:
    return (
        JamError,
        ObjectDoesNotExist,
        OverflowError,
        TypeError,
        ValidationError,
        ValueError,
    )


@sensitive_variables()
def authenticate_credential(
    credential: str,
    *,
    via: JamAuthType,
) -> Principal[Any]:
    """Authenticate and synchronously resolve a Django user."""
    try:
        principal = get_jam().authenticate(credential, via=via)
        user = get_user_model()._default_manager.get(pk=_subject_pk(principal))
    except JamConfigurationError:
        raise
    except _invalid_errors():
        raise InvalidCredential from None
    return adapt_principal(principal, user)


@sensitive_variables()
async def authenticate_credential_async(
    credential: str,
    *,
    via: JamAuthType,
) -> Principal[Any]:
    """Authenticate without blocking, then use Django's async ORM path."""
    try:
        principal = await get_async_jam().authenticate(credential, via=via)
        user = await get_user_model()._default_manager.aget(
            pk=_subject_pk(principal)
        )
    except JamConfigurationError:
        raise
    except _invalid_errors():
        raise InvalidCredential from None
    return adapt_principal(principal, user)


def reusable_principal(request: Any) -> Principal[Any] | None:
    """Return a Principal already verified for this Django request."""
    principal = getattr(request, "_jam_principal", None)
    user = getattr(request, "user", None)
    if (
        isinstance(principal, Principal)
        and principal.token_type in _AUTHENTICATED_TYPES
        and principal.subject == user
    ):
        return principal
    return None


def install_principal(request: Any, principal: Principal[Any]) -> None:
    """Install one identity consistently on Django's request APIs."""
    user = principal.subject
    request.user = user
    request._jam_principal = principal
    # Django permission backends only receive ``user_obj``. The ORM result is
    # unique to this request, so this request-local bridge cannot leak between
    # concurrent requests.
    user._jam_principal = principal

    async def auser() -> Any:
        return user

    request.auser = auser


@sensitive_variables()
def authenticate_request(
    request: Any,
    *,
    bearer: bool = True,
    session_source: CredentialSource | None = CredentialSource.cookie(
        "session"
    ),
) -> Principal[Any] | None:
    """Authenticate Bearer first, then an optional Jam Session source."""
    current = reusable_principal(request)
    if current is not None:
        return current
    enabled = configured_mechanisms()
    if bearer:
        credential = bearer_credential(request)
        if credential is not None:
            via = detect_bearer_type(credential)
            if via is None or via not in enabled:
                raise InvalidCredential
            return authenticate_credential(credential, via=via)
    if session_source is not None and "session" in enabled:
        credential = source_credential(request, session_source)
        if credential is not None:
            return authenticate_credential(credential, via="session")
    return None


@sensitive_variables()
async def authenticate_request_async(
    request: Any,
    *,
    bearer: bool = True,
    session_source: CredentialSource | None = CredentialSource.cookie(
        "session"
    ),
) -> Principal[Any] | None:
    """Async equivalent of :func:`authenticate_request`."""
    current = reusable_principal(request)
    if current is not None:
        return current
    enabled = configured_mechanisms()
    if bearer:
        credential = bearer_credential(request)
        if credential is not None:
            via = detect_bearer_type(credential)
            if via is None or via not in enabled:
                raise InvalidCredential
            return await authenticate_credential_async(credential, via=via)
    if session_source is not None and "session" in enabled:
        credential = source_credential(request, session_source)
        if credential is not None:
            return await authenticate_credential_async(
                credential,
                via="session",
            )
    return None
