# -*- coding: utf-8 -*-

"""Backward-compatible Bearer helpers for existing Django adapters."""

from __future__ import annotations

from typing import Any

from jam.authz import Principal
from jam.ext.django._authentication import (
    InvalidCredential,
    authenticate_credential,
    bearer_credential,
    detect_bearer_type,
)


InvalidBearerCredential = InvalidCredential


def get_bearer_credential(request: Any) -> str | None:
    """Extract a Bearer credential or return ``None`` for another scheme."""
    return bearer_credential(request)


def detect_token_type(token: str) -> str | None:
    """Classify JWT, JWE, and PASETO without cryptographic verification."""
    return detect_bearer_type(token)


def authenticate_bearer(request: Any) -> Principal[Any] | None:
    """Authenticate a Bearer token and adapt its subject to a Django user."""
    credential = get_bearer_credential(request)
    if credential is None:
        return None
    token_type = detect_token_type(credential)
    if token_type is None:
        raise InvalidBearerCredential
    return authenticate_credential(credential, via=token_type)
