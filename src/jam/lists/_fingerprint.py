# -*- coding: utf-8 -*-

"""Private token fingerprinting helpers for list storage."""

from hashlib import sha256

from jam.exceptions import JamValidationError


def token_fingerprint(token: str) -> str:
    """Return the SHA-256 fingerprint for a serialized token.

    Args:
        token (str): Serialized token to fingerprint.

    Returns:
        str: SHA-256 hexadecimal digest.

    Raises:
        JamValidationError: If the token is not a non-empty string.
    """
    if not isinstance(token, str) or not token:
        raise JamValidationError(
            message="Token must be a non-empty string.",
            error_code="validation.lists.invalid_token",
        )
    try:
        serialized = token.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise JamValidationError(
            message="Token must be valid UTF-8.",
            error_code="validation.lists.invalid_token",
        ) from exc
    return sha256(serialized).hexdigest()
