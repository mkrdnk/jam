# -*- coding: utf-8 -*-
# type: ignore

import hashlib
import hmac
import secrets
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
from jam.paseto.__base__ import BasePASETO, KeyLoadMixin
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__
from jam.utils.xchacha20poly1305 import xchacha20_xor


class PASETOv4(KeyLoadMixin, BasePASETO):
    """PASETO v4 factory."""

    _VERSION = "v4"
    _SUPPORTS_IMPLICIT_ASSERTION = True

    def _local_keys(self, nonce: bytes) -> tuple[bytes, bytes, bytes]:
        """Derive v4.local encryption, nonce and authentication keys."""
        encryption = hashlib.blake2b(
            b"paseto-encryption-key" + nonce,
            key=self._secret,
            digest_size=56,
        ).digest()
        authentication = hashlib.blake2b(
            b"paseto-auth-key-for-aead" + nonce,
            key=self._secret,
            digest_size=32,
        ).digest()
        return encryption[:32], encryption[32:], authentication

    def _encode_local(
        self,
        header: str,
        payload: bytes,
        footer: bytes,
        implicit_assertion: bytes,
    ) -> bytes:
        """Encode a standards-compliant v4.local token."""
        header_b = header.encode("ascii")
        nonce = secrets.token_bytes(32)
        encryption, stream_nonce, authentication = self._local_keys(nonce)
        ciphertext = xchacha20_xor(encryption, stream_nonce, payload)
        tag = hashlib.blake2b(
            __pae__([header_b, nonce, ciphertext, footer, implicit_assertion]),
            key=authentication,
            digest_size=32,
        ).digest()
        token = header_b + base64url_encode(nonce + ciphertext + tag)
        return token + (b"." + base64url_encode(footer) if footer else b"")

    def _decode_local(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder,
        implicit_assertion: bytes,
    ) -> tuple[Any, Any]:
        """Decode a standards-compliant v4.local token."""
        header, body_part, footer_part = self._parse_token(token, "local")
        body = base64url_decode(body_part)
        if len(body) < 64:
            raise JamPASETOInvalidTokenFormat(message="Invalid token body.")
        nonce, ciphertext, tag = body[:32], body[32:-32], body[-32:]
        footer = base64url_decode(footer_part) if footer_part else b""
        encryption, stream_nonce, authentication = self._local_keys(nonce)
        expected = hashlib.blake2b(
            __pae__([header, nonce, ciphertext, footer, implicit_assertion]),
            key=authentication,
            digest_size=32,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise JamPASETOKeyVerificationError(
                message="Invalid authentication tag."
            )
        plaintext = xchacha20_xor(encryption, stream_nonce, ciphertext)
        return serializer.loads(plaintext), self._decode_footer(
            footer, serializer
        )

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
        self,
        header: str,
        payload: bytes,
        footer: bytes,
        implicit_assertion: bytes,
    ) -> bytes:
        """Encode a 'public' token."""
        if not isinstance(self._secret, Ed25519PrivateKey):
            raise JamPASETOInvalidED25519Key(
                message="Private Ed25519 key required for v4.public signing"
            )
        header_b = header.encode("ascii")
        pre_auth = __pae__([header_b, payload, footer, implicit_assertion])
        signature = self._secret.sign(pre_auth)  # raw 64 bytes

        token = header_b + base64url_encode(payload + signature)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_public(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
        implicit_assertion: bytes = b"",
    ) -> tuple[Any, Any]:
        """Decode a 'public' token."""
        header, body_part, footer_part = self._parse_token(token, "public")
        body = base64url_decode(body_part)
        if len(body) < 64:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid token body (too short for Ed25519 signature)"
            )
        payload = body[:-64]
        signature = body[-64:]
        footer_decoded = base64url_decode(footer_part) if footer_part else b""

        pre_auth = __pae__(
            [header, payload, footer_decoded, implicit_assertion]
        )

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
