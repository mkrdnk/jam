# -*- coding: utf-8 -*-
# type: ignore

import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidED25519Key,
    JamPASETOInvalidPurpose,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
    JamPASTOKeyVerificationError,
)
from jam.paseto.__base__ import BasePASETO
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__
from jam.utils.xchacha20poly1305 import (
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)


class PASETOv4(BasePASETO):
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
            JamPASETOInvalidED25519Key: If the key is not a valid ED25519 key.
            JamPASETOInvalidPurpose: If the purpose is not "local" or "public".
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

        elif self._purpose == "public":
            # Ed25519 objects
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
            try:
                priv = serialization.load_pem_private_key(
                    key_bytes, password=None
                )
                if isinstance(priv, Ed25519PrivateKey):
                    self._secret = priv
                    self._public_key = priv.public_key()
                    return
            except Exception:
                pass
            try:
                priv = serialization.load_der_private_key(
                    key_bytes, password=None
                )
                if isinstance(priv, Ed25519PrivateKey):
                    self._secret = priv
                    self._public_key = priv.public_key()
                    return
            except Exception:
                pass
            try:
                pub = serialization.load_pem_public_key(key_bytes)
                if isinstance(pub, Ed25519PublicKey):
                    self._secret = None
                    self._public_key = pub
                    return
            except Exception:
                pass
            try:
                pub = serialization.load_der_public_key(key_bytes)
                if isinstance(pub, Ed25519PublicKey):
                    self._secret = None
                    self._public_key = pub
                    return
            except Exception:
                pass

            raise JamPASETOInvalidED25519Key(
                message="Invalid Ed25519 key for v4.public."
            )

    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | bytes | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> str:
        """Encode PASETO.

        Args:
            payload (dict[str, Any]): PASETO Payload
            footer (dict[str, Any] | str | None): Footer if needed
            serializer (type[BaseEncoder] | BaseEncoder): JSON Serializer

        Returns:
            str: PASETO

        Raises:
            JamPASETOInvalidED25519Key: If the key is not a valid ED25519 key.
            JamPASETOInvalidPurpose: If the purpose is not "local" or "public".
        """
        header = f"{self._VERSION}.{self._purpose}."
        payload_bytes = serializer.dumps(payload)

        if isinstance(footer, (dict | list)):
            footer_bytes = serializer.dumps(footer)
        elif isinstance(footer, str):
            footer_bytes = footer.encode("utf-8")
        elif isinstance(footer, (bytes | bytearray)):
            footer_bytes = bytes(footer)
        else:
            footer_bytes = b""

        if self._purpose == "local":
            token = self._encode_local(
                header, payload_bytes, footer_bytes
            ).decode("utf-8")
        elif self._purpose == "public":
            token = self._encode_public(
                header, payload_bytes, footer_bytes
            ).decode("utf-8")
        else:
            raise JamPASETOInvalidPurpose

        self._list_add(token)
        return token

    def decode(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[dict[str, Any], dict[str, Any] | str | bytes | None]:
        """Decode PASETO.

        Args:
            token (str): PASETO
            serializer (type[BaseEncoder] | BaseEncoder]): JSON Serializer

        Raises:
            JamPASETOInvalidTokenFormat: If the token format is invalid.
            JamPASETOInvalidED25519Key: If the key is not a valid ED25519 key.
            JamPASETOKeyVerificationError: If the token signature is invalid.
            JamPASETOInvalidPurpose: If the purpose is not "local" or "public".
        """
        self._list_check(token)
        if token.startswith(f"{self._VERSION}.local."):
            return self._decode_local(token, serializer)
        elif token.startswith(f"{self._VERSION}.public."):
            return self._decode_public(token, serializer)
        else:
            raise JamPASETOInvalidPurpose

    def _encode_local(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        header_b = header.encode("ascii")
        nonce = secrets.token_bytes(24)
        aad = __pae__([header_b, footer or b""])
        ciphertext = xchacha20poly1305_encrypt(
            self._secret, nonce, payload, aad
        )

        token = header_b + base64url_encode(nonce + ciphertext)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_local(
        self, token: str, serializer: BaseEncoder | type[BaseEncoder]
    ):
        parts = token.encode("utf-8").split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat(message="Invalid token format")
        header = b".".join(parts[:2]) + b"."
        if header != b"v4.local.":
            raise JamPASETOInvalidTokenFormat(message="Invalid header")

        body = base64url_decode(parts[2])
        if len(body) < 24 + 16:
            raise JamPASETOInvalidTokenFormat(message="Invalid token body")

        nonce = body[:24]
        ciphertext = body[24:]
        footer_part = parts[3] if len(parts) > 3 else b""
        footer_decoded = base64url_decode(footer_part) if footer_part else b""

        aad = __pae__([header, footer_decoded])
        try:
            plaintext = xchacha20poly1305_decrypt(
                self._secret, nonce, ciphertext, aad
            )
        except Exception:
            raise JamPASTOKeyVerificationError(
                message="Invalid authentication or corrupt ciphertext"
            )

        payload = serializer.loads(plaintext)

        footer_val = None
        if footer_decoded:
            try:
                footer_val = serializer.loads(footer_decoded)
            except Exception:
                try:
                    footer_val = footer_decoded.decode("utf-8")
                except Exception:
                    footer_val = footer_decoded

        return payload, footer_val

    def _encode_public(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        if not hasattr(self._secret, "sign") or not isinstance(
            self._secret, Ed25519PrivateKey
        ):
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

    def _decode_public(self, token: str, serializer: BaseEncoder):
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
            # raises InvalidSignature on failure
            self._public_key.verify(signature, pre_auth)
        except Exception:
            raise JamPASTOKeyVerificationError(message="Invalid signature")

        payload_data = serializer.loads(payload)

        footer_val = None
        if footer_decoded:
            try:
                footer_val = serializer.loads(footer_decoded)
            except Exception:
                try:
                    footer_val = footer_decoded.decode("utf-8")
                except Exception:
                    footer_val = footer_decoded

        return payload_data, footer_val
