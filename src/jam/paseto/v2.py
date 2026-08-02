# -*- coding: utf-8 -*-
# type: ignore

import base64
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidED25519Key,
    JamPASETOInvalidPurpose,
    JamPASETOInvalidTokenFormat,
)
from jam.paseto.__base__ import BasePASETO
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__
from jam.utils.xchacha20poly1305 import (
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)


class PASETOv2(BasePASETO):
    """PASETO v2 factory."""

    _VERSION = "v2"

    def _set_key(
        self,
        secret_key: str | bytes | Ed25519PrivateKey | Ed25519PublicKey,
    ) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes): Secret or Ed25519 key.
        """
        if self._purpose == "local":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
                secret_key = base64.urlsafe_b64decode(secret_key + "==")
            if not isinstance(secret_key, bytes) or len(secret_key) != 32:
                raise ValueError("v2.local key must be 32 bytes")
            self._secret = secret_key
            return

        elif self._purpose == "public":
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

            if isinstance(secret_key, str):
                secret_key = secret_key.encode()

            try:
                private_key = serialization.load_pem_private_key(
                    secret_key, password=None
                )
                if not isinstance(private_key, Ed25519PrivateKey):
                    raise ValueError("Expected Ed25519 private key")
                self._secret = private_key
                self._public_key = private_key.public_key()
                return
            except Exception:
                try:
                    public_key = serialization.load_pem_public_key(secret_key)
                    if not isinstance(public_key, Ed25519PublicKey):
                        raise JamPASETOInvalidED25519Key(
                            message="Expected Ed25519 public key",
                            error_code="paseto.config.expected_ed25519_public_key",
                        )
                    self._secret = None
                    self._public_key = public_key
                    return
                except Exception:
                    raise JamPASETOInvalidED25519Key

    def _encode_local(
        self,
        header: str,
        payload: bytes,
        footer: bytes | None,
    ) -> bytes:
        bheader = header.encode("ascii")
        bfooter = footer or b""
        nonce = secrets.token_bytes(24)
        aad = __pae__([bheader, bfooter])

        ciphertext = xchacha20poly1305_encrypt(
            self._secret, nonce, payload, aad
        )

        token = bheader + base64url_encode(nonce + ciphertext)
        if bfooter:
            token += b"." + base64url_encode(bfooter)
        return token

    def _encode_public(
        self, header: str, payload: bytes, footer: bytes | None
    ) -> bytes:
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

    def _decode_local(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        parts = token.encode().split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat

        header = b".".join(parts[:2]) + b"."
        if header != b"v2.local.":
            raise JamPASETOInvalidTokenFormat(
                message="Invalid PASETO header",
                error_code="paseto.validation.invalid_header",
            )

        body = base64url_decode(parts[2])
        footer = base64url_decode(parts[3]) if len(parts) > 3 else b""

        nonce = body[:24]
        ciphertext = body[24:]
        aad = __pae__([header, footer])

        try:
            plaintext = xchacha20poly1305_decrypt(
                self._secret, nonce, ciphertext, aad
            )
        except Exception:
            raise JamPASETOInvalidED25519Key(
                "Invalid authentication or corrupt ciphertext"
            )

        payload = serializer.loads(plaintext)

        footer_val = None
        if footer:
            try:
                footer_val = serializer.loads(footer)
            except Exception:
                try:
                    footer_val = footer.decode("utf-8")
                except Exception:
                    footer_val = footer

        return payload, footer_val

    def _decode_public(
        self,
        token: str,
        serializer,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
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
            raise JamPASETOInvalidTokenFormat

        payload_data = serializer.loads(payload)

        footer_val = None
        if footer:
            try:
                footer_val = serializer.loads(footer)
            except Exception:
                try:
                    footer_val = footer.decode("utf-8")
                except Exception:
                    footer_val = footer

        return payload_data, footer_val

    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> str:
        """Encode."""
        header = f"{self._VERSION}.{self._purpose}."
        payload = serializer.dumps(payload)
        footer = serializer.dumps(footer) if footer else None
        if self._purpose == "local":
            token = self._encode_local(header, payload, footer).decode("utf-8")
        elif self._purpose == "public":
            token = self._encode_public(header, payload, footer).decode("utf-8")
        else:
            raise JamPASETOInvalidPurpose

        self._list_add(token)
        return token

    def decode(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Decode."""
        self._list_check(token)
        if token.startswith(f"{self._VERSION}.local"):
            return self._decode_local(token, serializer)
        elif token.startswith(f"{self._VERSION}.public"):
            return self._decode_public(token, serializer)
        else:
            raise JamPASETOInvalidPurpose
