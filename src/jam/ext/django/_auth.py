# -*- coding: utf-8 -*-

"""Shared Bearer authentication helpers for Django adapters."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist, ValidationError

from jam.authz import Principal
from jam.exceptions import JamConfigurationError, JamError
from jam.ext._base import DEFAULT_SOURCES, _extract_credential
from jam.ext.django.runtime import get_jam


_PASETO_PREFIX = re.compile(r"^v[1-4]\.(?:local|public)\.")


class InvalidBearerCredential(Exception):
    """Raised when an explicitly supplied Bearer credential is invalid."""


def get_bearer_credential(request: Any) -> str | None:
    """Extract a Bearer credential or return ``None`` for another scheme."""
    value = request.headers.get("Authorization")
    if value is None:
        return None
    scheme, separator, credential = value.partition(" ")
    if scheme.casefold() != "bearer":
        return None
    if not separator or not credential.strip():
        raise InvalidBearerCredential
    token, _source = _extract_credential(
        DEFAULT_SOURCES,
        headers=request.headers,
        cookies={},
        query=None,
    )
    if not token:
        raise InvalidBearerCredential
    return token


def detect_token_type(token: str) -> str | None:
    """Classify JWT and PASETO without cryptographic verification."""
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


def authenticate_bearer(request: Any) -> Principal[Any] | None:
    """Authenticate a Bearer token and adapt its subject to a Django user."""
    credential = get_bearer_credential(request)
    if credential is None:
        return None
    token_type = detect_token_type(credential)
    if token_type is None:
        raise InvalidBearerCredential
    try:
        token_principal = get_jam().authenticate(credential, via=token_type)
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
    ) as error:
        raise InvalidBearerCredential from error
    return Principal(
        subject=user,
        claims=token_principal.claims,
        token_type=token_principal.token_type,
    )
