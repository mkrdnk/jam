# -*- coding: utf-8 -*-
# type: ignore

import hashlib
import hmac
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidRSAKey,
    JamPASETOInvalidTokenFormat,
    JamPASTOKeyVerificationError,
)
from jam.exceptions.paseto import JamPASETOInvalidPurpose
from jam.paseto.__base__ import BasePASETO
from jam.paseto.utils import (
    __gen_hash__,
    __pae__,
    base64url_decode,
    base64url_encode,
)
from jam.utils.config_maker import __key_loader__


class PASETOv1(BasePASETO):
    """Paseto v1 factory."""

    _VERSION = "v1"

    def _set_key(
        self, secret_key: str | bytes | None | RSAPrivateKey | RSAPublicKey
    ) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes): PEM or secret key

        Raises:
            JamPASETOInvalidRSAKey: If the key is invalid.
        """
        if self._purpose == "local":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
                raw = base64url_decode(secret_key.encode("utf-8"))
            else:
                raw = secret_key
            if not isinstance(raw, (bytes, bytearray) or len(raw) != 32):  # type: ignore[bad-argument-type]
                raise JamPASETOInvalidRSAKey(
                    message="v1.local requires a 32-byte secret key.",
                    details={
                        "version": "v1",
                        "purpose": "local",
                        "key": secret_key,
                    },
                )
            self._secret = bytes(raw)
            return

        elif self._purpose == "public":
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
            try:
                priv = serialization.load_pem_private_key(
                    key_bytes,  # type: ignore[arg-type]
                    password=None,
                )
                if isinstance(priv, RSAPrivateKey):
                    self._secret = priv
                    self._public_key = priv.public_key()
                    return
            except Exception:
                pass
            try:
                priv = serialization.load_der_private_key(  # type: ignore[arg-type]
                    key_bytes,
                    password=None,
                )
                if isinstance(priv, RSAPrivateKey):
                    self._secret = priv
                    self._public_key = priv.public_key()
                    return
            except Exception:
                pass
            try:
                pub = serialization.load_pem_public_key(key_bytes)  # type: ignore[arg-type]
                if isinstance(pub, RSAPublicKey):
                    self._secret = None
                    self._public_key = pub
                    return
            except Exception:
                pass
            try:
                pub = serialization.load_der_public_key(key_bytes)  # type: ignore[arg-type]
                if isinstance(pub, RSAPublicKey):
                    self._secret = None
                    self._public_key = pub
                    return
            except Exception:
                pass

            raise JamPASETOInvalidRSAKey(
                message="Invalid RSA key for v1.public"
            )

    def _encode_local(
        self,
        header: str,
        payload: bytes,
        footer: bytes,
    ) -> bytes:
        header_bytes = header.encode("ascii")
        nonce = secrets.token_bytes(32)
        pl = __gen_hash__(nonce, payload, 32)

        hkdf_params = {
            "algorithm": hashes.SHA384(),
            "length": 32,
            "salt": pl[0:16],
        }
        ek = HKDF(info=b"paseto-encryption-key", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )
        ak = HKDF(info=b"paseto-auth-key-for-aead", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )

        ciphertext = self._encrypt(ek, pl[16:], payload)
        pre_auth = __pae__([header_bytes, pl, ciphertext, footer])
        tag = hmac.new(ak, pre_auth, hashlib.sha384).digest()

        token = header_bytes + base64url_encode(pl + ciphertext + tag)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _encode_public(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        header_bytes = header.encode("ascii")
        pre_auth = __pae__([header_bytes, payload, footer])

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
            raise JamPASTOKeyVerificationError(
                details={"version": "v1", "error": str(e)}
            )

        token = header_bytes + base64url_encode(payload + signature)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_local(self, token: str, serializer):
        """Decode local PASETO."""
        parts = token.encode("utf-8").split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat

        header = b".".join(parts[:2]) + b"."
        if header != b"v1.local.":
            raise JamPASETOInvalidTokenFormat(
                message="Invalid PASETO header",
                error_code="paseto.validation.invalid_header",
            )

        payload_part = parts[2]
        footer_part = parts[3] if len(parts) > 3 else b""

        decoded = base64url_decode(payload_part)
        if len(decoded) < 80:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid payload size.",
                error_code="paseto.validation.invalid_payload_size",
            )

        pl = decoded[:32]
        ciphertext_tag = decoded[32:]
        tag = ciphertext_tag[-48:]
        ciphertext = ciphertext_tag[:-48]

        footer_decoded = base64url_decode(footer_part) if footer_part else b""

        hkdf_params = {
            "algorithm": hashes.SHA384(),
            "length": 32,
            "salt": pl[0:16],
        }
        ek = HKDF(info=b"paseto-encryption-key", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )
        ak = HKDF(info=b"paseto-auth-key-for-aead", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )

        pre_auth = __pae__([header, pl, ciphertext, footer_decoded])
        expected_tag = hmac.new(ak, pre_auth, hashlib.sha384).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise JamPASETOInvalidTokenFormat(
                message="Invalid authentication tag",
                error_code="paseto.validation.invalid_authentication_tag",
            )

        payload_bytes = self._decrypt(ek, pl[16:], ciphertext)
        payload = serializer.loads(payload_bytes)

        # FIXME: Optimize
        footer = None
        if footer_decoded:
            try:
                footer = serializer.loads(footer_decoded)
            except Exception:
                try:
                    footer = footer_decoded.decode("utf-8")
                except Exception:
                    footer = footer_decoded

        return payload, footer

    def _decode_public(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ):
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
            raise JamPASTOKeyVerificationError

        payload_data = serializer.loads(payload)

        footer = None
        if footer_decoded:
            try:
                footer = serializer.loads(footer_decoded)
            except Exception:
                try:
                    footer = footer_decoded.decode("utf-8")
                except Exception:
                    footer = footer_decoded

        return payload_data, footer

    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> str:
        """Encode PASETO."""
        header = f"{self._VERSION}.{self.purpose}."
        payload = serializer.dumps(payload)
        footer = serializer.dumps(footer) if footer else b""

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
        """Decode PASETO.

        Args:
            token (str): PASETO
            serializer (BaseEncoder): Json serializer
        """
        self._list_check(token)
        if token.startswith(f"{self._VERSION}.local"):
            return self._decode_local(token, serializer)
        elif token.startswith(f"{self._VERSION}.public"):
            return self._decode_public(token, serializer)
        else:
            raise JamPASETOInvalidPurpose
