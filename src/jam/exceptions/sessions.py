# -*- coding: utf-8 -*-

from .base import JamConfigurationError, JamError, JamValidationError


class JamSessionNotFound(JamError):
    """Raised when a requested session does not exist."""

    default_message = "Session not found."
    default_code = "sessions.not_found"


class JamSessionExpired(JamValidationError):
    """Raised when a persisted session has expired."""

    default_message = "Session lifetime expired."
    default_code = "sessions.expired"


class JamSessionNotYetValid(JamValidationError):
    """Raised when a session is used before its validity window."""

    default_message = "Session is not yet valid."
    default_code = "sessions.not_yet_valid"


class JamSessionInvalidClaim(JamValidationError):
    """Raised when a session time claim is not a finite NumericDate."""

    default_message = "Session claim has an invalid value."
    default_code = "sessions.invalid_claim"


class JamSessionEmptyAESKey(JamConfigurationError):
    """Raised when encrypted sessions have no configured AES key."""

    default_message = "Session AES key is empty."
    default_code = "sessions.empty_aes_key"
