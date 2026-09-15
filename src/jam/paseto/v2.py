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


class PASETOv2(XChaChaMixin, KeyLoadMixin, BasePASETO):
    """PASETO v2 factory."""

    _VERSION = "v2"

    def _set_key(
        self,
        secret_key: str | bytes | Ed25519PrivateKey | Ed25519PublicKey,
    ) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes): Secret or Ed25519 key.

        Raises:
            JamPASETOInvalidSymmetricKey: If the local key is invalid.
            JamPASETOInvalidED25519Key: If the Ed25519 key is invalid.
        """
        if self._purpose == "local":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
                secret_key = base64url_decode(secret_key.encode("utf-8"))
            if not isinstance(secret_key, bytes) or len(secret_key) != 32:
                raise JamPASETOInvalidSymmetricKey(
                    "v2.local key must be 32 bytes"
                )
            self._secret = secret_key
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
                secret_key.encode()
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
                message="Invalid Ed25519 key for v2.public"
            )

    def _encode_public(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        """Encode a 'public' token."""
        bheader = header.encode("ascii")
        footer_bytes = footer or b""

        if not isinstance(self._secret, Ed25519PrivateKey):
            raise JamPASETOInvalidED25519Key(
                message="Secret key must be Ed25519PrivateKey for v2.public",
                error_code="paseto.config.v2_key_format_error",
            )

        pre_auth = __pae__([bheader, payload, footer_bytes])
        signature = self._secret.sign(pre_auth)

        token = bheader + base64url_encode(payload + signature)
        if footer_bytes:
            token += b"." + base64url_encode(footer_bytes)
        return token

    def _decode_public(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[Any, Any]:
        """Decode a 'public' token."""
        parts = token.encode().split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat

        header = b".".join(parts[:2]) + b"."
        if header != b"v2.public.":
            raise JamPASETOInvalidTokenFormat(
                message="Invalid header",
                error_code="paseto.validation.invalid_header",
            )

        body = base64url_decode(parts[2])
        footer = base64url_decode(parts[3]) if len(parts) > 3 else b""

        if len(body) < 64:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid token: too short to contain Ed25519 signature",
                error_code="paseto.validation.invalid_payload_size",
            )

        payload = body[:-64]
        signature = body[-64:]
        pre_auth = __pae__([header, payload, footer])

        if not isinstance(self._public_key, Ed25519PublicKey):
            raise JamPASETOInvalidED25519Key(
                message="Public key must be Ed25519PublicKey for v2.public",
                error_code="paseto.configuration.invalid_ed25519_key",
            )

        try:
            self._public_key.verify(signature, pre_auth)
        except Exception:
            raise JamPASETOKeyVerificationError(message="Invalid signature")

        return (
            serializer.loads(payload),
            self._decode_footer(footer, serializer),
        )
