# -*- coding: utf-8 -*-
# type: ignore

from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidRSAKey,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
    JamPASETOKeyVerificationError,
)
from jam.paseto.__base__ import BasePASETO, KeyLoadMixin, LegacyAEADMixin
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__


class PASETOv1(LegacyAEADMixin, KeyLoadMixin, BasePASETO):
    """Paseto v1 factory."""

    _VERSION = "v1"

    def _set_key(
        self, secret_key: str | bytes | None | RSAPrivateKey | RSAPublicKey
    ) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes): PEM or secret key

        Raises:
            JamPASETOInvalidSymmetricKey: If the local key is invalid.
            JamPASETOInvalidRSAKey: If the RSA key is invalid.
        """
        if self._purpose == "local":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
                raw = base64url_decode(secret_key.encode("utf-8"))
            else:
                raw = secret_key
            if not isinstance(raw, bytes | bytearray) or len(raw) != 32:
                raise JamPASETOInvalidSymmetricKey(
                    message="v1.local requires a 32-byte secret key.",
                    details={
                        "version": "v1",
                        "purpose": "local",
                        "key": secret_key,
                    },
                )
            self._secret = bytes(raw)
            return

        if self._purpose == "public":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
            if isinstance(secret_key, RSAPrivateKey):
                self._secret = secret_key
                self._public_key = secret_key.public_key()
                return
            if isinstance(secret_key, RSAPublicKey):
                self._secret = None
                self._public_key = secret_key
                return

            key_bytes = (
                secret_key.encode("utf-8")
                if isinstance(secret_key, str)
                else secret_key
            )
            priv, pub = self._load_key(
                key_bytes, (RSAPrivateKey,), (RSAPublicKey,)
            )
            if priv is not None:
                self._secret = priv
                self._public_key = priv.public_key()
                return
            if pub is not None:
                self._secret = None
                self._public_key = pub
                return

            raise JamPASETOInvalidRSAKey(
                message="Invalid RSA key for v1.public"
            )

    def _encode_public(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        """Encode a 'public' token."""
        header_b = header.encode("ascii")
        pre_auth = __pae__([header_b, payload, footer])

        try:
            signature = self._secret.sign(
                pre_auth,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA384(),
            )
        except Exception as e:
            raise JamPASETOKeyVerificationError(
                details={"version": "v1", "error": str(e)}
            )

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
            raise JamPASETOInvalidTokenFormat

        header = b".".join(parts[:2]) + b"."
        if header != b"v1.public.":
            raise JamPASETOInvalidTokenFormat(
                message="Invalid PASETO header",
                error_code="paseto.validation.invalid_header",
            )

        payload_part = parts[2]
        footer_part = parts[3] if len(parts) > 3 else b""

        decoded = base64url_decode(payload_part)
        if len(decoded) < 256:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid token body,",
                error_code="paseto.validation.invalid_body",
            )

        key_size = self._public_key.key_size // 8
        if len(decoded) < key_size:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid payload/signature size",
                error_code="paseto.validation.invalid_payload_signature_size",
            )

        payload = decoded[:-key_size]
        signature = decoded[-key_size:]

        footer_decoded = base64url_decode(footer_part) if footer_part else b""

        pre_auth = __pae__([header, payload, footer_decoded])
        try:
            self._public_key.verify(
                signature,
                pre_auth,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA384(),
            )
        except Exception:
            raise JamPASETOKeyVerificationError

        return (
            serializer.loads(payload),
            self._decode_footer(footer_decoded, serializer),
        )
