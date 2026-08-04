# -*- coding: utf-8 -*-
# type: ignore

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidED25519Key,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
    JamPASETOKeyVerificationError,
)
from jam.paseto.__base__ import BasePASETO, KeyLoadMixin, XChaChaMixin
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__


class PASETOv4(XChaChaMixin, KeyLoadMixin, BasePASETO):
    """PASETO v4 factory."""

    _VERSION = "v4"

    def _set_key(
        self,
        secret_key: str | bytes | Ed25519PrivateKey,
    ) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes | Ed25519PrivateKey): Secret or ED Private key

        Raises:
            JamPASETOInvalidSymmetricKey: If the local key is invalid.
            JamPASETOInvalidED25519Key: If the key is not a valid ED25519 key.
        """
        if self._purpose == "local":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
                raw = base64url_decode(secret_key.encode("utf-8"))
            else:
                raw = secret_key
            if not isinstance(raw, (bytes | bytearray)) or len(raw) != 32:
                raise JamPASETOInvalidSymmetricKey(
                    message="v4.local requires a 32-byte secret key."
                )
            self._secret = bytes(raw)
            return

        if self._purpose == "public":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
            if isinstance(secret_key, Ed25519PrivateKey):
                self._secret = secret_key
                self._public_key = secret_key.public_key()
                return
            if isinstance(secret_key, Ed25519PublicKey):
                self._secret = None
                self._public_key = secret_key
                return

            key_bytes = (
                secret_key.encode("utf-8")
                if isinstance(secret_key, str)
                else secret_key
            )
            priv, pub = self._load_key(
                key_bytes, (Ed25519PrivateKey,), (Ed25519PublicKey,)
            )
            if priv is not None:
                self._secret = priv
                self._public_key = priv.public_key()
                return
            if pub is not None:
                self._secret = None
                self._public_key = pub
                return

            raise JamPASETOInvalidED25519Key(
                message="Invalid Ed25519 key for v4.public."
            )

    def _encode_public(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        """Encode a 'public' token."""
        if not isinstance(self._secret, Ed25519PrivateKey):
            raise JamPASETOInvalidED25519Key(
                message="Private Ed25519 key required for v4.public signing"
            )
        header_b = header.encode("ascii")
        pre_auth = __pae__([header_b, payload, footer or b""])
        signature = self._secret.sign(pre_auth)  # raw 64 bytes

        token = header_b + base64url_encode(payload + signature)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_public(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[Any, Any]:
        """Decode a 'public' token."""
        parts = token.encode("utf-8").split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat(message="Invalid token format.")
        header = b".".join(parts[:2]) + b"."
        if header != b"v4.public.":
            raise JamPASETOInvalidTokenFormat(message="Invalid header.")

        body = base64url_decode(parts[2])
        if len(body) < 64:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid token body (too short for Ed25519 signature)"
            )
        payload = body[:-64]
        signature = body[-64:]
        footer_part = parts[3] if len(parts) > 3 else b""
        footer_decoded = base64url_decode(footer_part) if footer_part else b""

        pre_auth = __pae__([header, payload, footer_decoded])

        if not self._public_key:
            raise JamPASETOInvalidED25519Key(
                message="Public key required for v4.public verification"
            )
        try:
            self._public_key.verify(signature, pre_auth)
        except Exception:
            raise JamPASETOKeyVerificationError(message="Invalid signature")

        return (
            serializer.loads(payload),
            self._decode_footer(footer_decoded, serializer),
        )
