# -*- coding: utf-8 -*-

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import logging
import math
import re
import struct
import time
from typing import Any

from jam.exceptions import (
    JamPASETOExpired,
    JamPASETOInvalidClaim,
    JamPASETOInvalidTokenFormat,
    JamPASETONotYetValid,
)


logger = logging.getLogger(__name__)


_RFC3339_DATETIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


def __gen_hash__(key: bytes, msg: bytes, hash_size: int = 0) -> bytes:
    """Generate hash."""
    try:
        hash_ = hmac.new(key, msg, hashlib.sha384).digest()
        return hash_[0:hash_size] if hash_size > 0 else hash_
    except Exception as e:
        raise ValueError(f"Failed to generate hash: {e}")


def __pae__(pieces: list[bytes]) -> bytes:
    """Pre-Authentication Encoding (PAE) as per PASETO spec."""
    output = struct.pack("<Q", len(pieces))
    for piece in pieces:
        output += struct.pack("<Q", len(piece))
        output += piece
    return output


def base64url_decode(v: str | bytes) -> bytes:
    """Decode an unpadded, canonical Base64url value."""
    try:
        bv = v if isinstance(v, bytes) else v.encode("ascii")
        if not bv or b"=" in bv:
            raise ValueError("padding is not allowed")
        if any(
            not (
                ord("A") <= character <= ord("Z")
                or ord("a") <= character <= ord("z")
                or ord("0") <= character <= ord("9")
                or character in (ord("-"), ord("_"))
            )
            for character in bv
        ):
            raise ValueError("invalid Base64url character")
        rem = len(bv) % 4
        if rem == 1:
            raise ValueError("invalid Base64url length")
        decoded = base64.b64decode(
            bv + b"=" * ((4 - rem) % 4), altchars=b"-_", validate=True
        )
        if base64url_encode(decoded) != bv:
            raise ValueError("non-canonical Base64url value")
        return decoded
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise JamPASETOInvalidTokenFormat(
            message=f"Invalid Base64url value: {exc}"
        ) from exc


def base64url_encode(data: bytes | str) -> bytes:
    """Base64 URL-safe encoding without padding."""
    if isinstance(data, bytes):
        bv = data
    else:
        bv = data.encode("ascii")
    return base64.urlsafe_b64encode(bv).replace(b"=", b"")


def _format_registered_datetime(timestamp: int | float) -> str:
    """Format a timestamp as the preferred PASETO RFC 3339 DateTime."""
    value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_registered_datetime(claim: str, value: Any) -> int | float:
    """Parse a PASETO DateTime, accepting legacy NumericDate values.

    Args:
        claim: Registered claim name.
        value: Claim value to parse.

    Returns:
        int | float: Comparable Unix timestamp.

    Raises:
        JamPASETOInvalidClaim: If the value is not an RFC 3339 DateTime or a
            finite legacy NumericDate.
    """
    if (
        not isinstance(value, bool)
        and isinstance(value, int | float)
        and (not isinstance(value, float) or math.isfinite(value))
    ):
        return value

    if isinstance(value, str) and _RFC3339_DATETIME.fullmatch(value):
        iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            return datetime.fromisoformat(iso_value).timestamp()
        except (OSError, OverflowError, ValueError):
            pass

    raise JamPASETOInvalidClaim(
        details={
            "claim": claim,
            "value": value,
            "expected": "RFC 3339 DateTime or finite legacy NumericDate",
        }
    )


def _validate_registered_claims(payload: dict[str, Any]) -> None:
    """Validate PASETO time-based registered claims.

    RFC 3339 DateTime strings are the standard PASETO representation. Finite
    NumericDate values remain accepted for tokens issued by older Jam versions.

    Args:
        payload: Authenticated PASETO payload.

    Raises:
        JamPASETOExpired: If the current time is later than ``exp``.
        JamPASETONotYetValid: If the current time is earlier than ``nbf``.
        JamPASETOInvalidClaim: If a claim has an invalid representation.
    """
    now = time.time()
    if "exp" in payload:
        expires_at = _parse_registered_datetime("exp", payload["exp"])
        if now > expires_at:
            logger.warning("Rejected expired PASETO")
            raise JamPASETOExpired(details={"exp": expires_at, "now": now})

    if "nbf" in payload:
        valid_from = _parse_registered_datetime("nbf", payload["nbf"])
        if now < valid_from:
            logger.warning("Rejected PASETO that is not yet valid")
            raise JamPASETONotYetValid(details={"nbf": valid_from, "now": now})
