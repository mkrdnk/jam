# -*- coding: utf-8 -*-

import base64
from datetime import datetime
import hashlib
import hmac
import struct
from typing import Any
from uuid import uuid4

from jam.exceptions import JamPASETOInvalidTokenFormat


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


def payload_maker(expire: int | None, data: dict[str, Any]) -> dict[str, Any]:
    """Generate PASETO payload.

    ```json
    {
        'iat': 1761326685.45693,
        'exp': 1761328485.45693,
        'pit': '52aeaf12-0825-4bc1-aa45-5ded41df2463',
        # custom data
        'user': 1,
        'role': 'admin'
    }
    ```

    Args:
        expire (int | None): Token lifetime
        data (dict[str, Any]): Custom data

    Returns:
        dict: Payload
    """
    now = datetime.now().timestamp()
    _payload = {
        "iat": now,
        "exp": (expire + now) if expire else None,
        "pit": str(uuid4()),
    }

    return _payload | data
