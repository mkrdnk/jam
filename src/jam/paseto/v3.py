# -*- coding: utf-8 -*-
# type: ignore

import hashlib
import hmac
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidSecp384r1Key,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
)
from jam.paseto.__base__ import BasePASETO, KeyLoadMixin
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__


class PASETOv3(KeyLoadMixin, BasePASETO):
    """PASETO v3 factory."""

    _VERSION = "v3"

    def _encode_local(
        self,
        header: str,
        payload: bytes,
        footer: bytes,
        implicit_assertion: bytes,
    ) -> bytes:
        """Encode a standards-compliant v3.local token."""
        header_b = header.encode("ascii")
        nonce = secrets.token_bytes(32)
        encryption = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-encryption-key" + nonce,
        ).derive(self._secret)
        authentication = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-auth-key-for-aead" + nonce,
        ).derive(self._secret)
        ciphertext = (
            Cipher(algorithms.AES(encryption[:32]), modes.CTR(encryption[32:]))
            .encryptor()
            .update(payload)
        )
        tag = hmac.new(
            authentication,
            __pae__([header_b, nonce, ciphertext, footer, implicit_assertion]),
            hashlib.sha384,
        ).digest()
        token = header_b + base64url_encode(nonce + ciphertext + tag)
        return token + (b"." + base64url_encode(footer) if footer else b"")

    def _decode_local(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder,
        implicit_assertion: bytes,
    ) -> tuple[Any, Any]:
        """Decode a standards-compliant v3.local token."""
        header, body_part, footer_part = self._parse_token(token, "local")
        body = base64url_decode(body_part)
        if len(body) < 80:
            raise JamPASETOInvalidTokenFormat(message="Invalid token body.")
        nonce, ciphertext, tag = body[:32], body[32:-48], body[-48:]
        footer = base64url_decode(footer_part) if footer_part else b""
        encryption = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-encryption-key" + nonce,
        ).derive(self._secret)
        authentication = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-auth-key-for-aead" + nonce,
        ).derive(self._secret)
        expected = hmac.new(
            authentication,
            __pae__([header, nonce, ciphertext, footer, implicit_assertion]),
            hashlib.sha384,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise JamPASETOInvalidTokenFormat(
                message="Invalid authentication tag."
            )
        plaintext = (
            Cipher(algorithms.AES(encryption[:32]), modes.CTR(encryption[32:]))
            .decryptor()
            .update(ciphertext)
        )
        return serializer.loads(plaintext), self._decode_footer(
            footer, serializer
        )

    def _set_key(self, secret_key: str | bytes) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes): Private PEM or secret key.

        Raises:
            JamPASETOInvalidSymmetricKey: If the local key is invalid.
            JamPASETOInvalidSecp384r1Key: If the EC key is not P-384.
        """
        if self._purpose == "local":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
                try:
                    raw = base64url_decode(secret_key.encode("utf-8"))
                except Exception:
                    raise JamPASETOInvalidSymmetricKey(
                        message="v3.local key string must be base64-url encoded 32 bytes",
                    )
            else:
                raw = secret_key
            if not isinstance(raw, (bytes | bytearray)) or len(raw) != 32:
                raise JamPASETOInvalidSymmetricKey(
                    "v3.local requires a 32-byte secret key"
                )
            self._secret = bytes(raw)
            return

        if self._purpose == "public":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
            if isinstance(secret_key, ec.EllipticCurvePrivateKey):
                if secret_key.curve.name != "secp384r1":
                    raise JamPASETOInvalidSecp384r1Key(
                        "PASETOv3.public requires P-384 (secp384r1) keys"
                    )
                self._secret = secret_key
                self._public_key = secret_key.public_key()
                return

            if isinstance(secret_key, ec.EllipticCurvePublicKey):
                if secret_key.curve.name != "secp384r1":
                    raise JamPASETOInvalidSecp384r1Key(
                        "PASETOv3.public requires P-384 (secp384r1) keys"
                    )
                self._secret = None
                self._public_key = secret_key
                return

            key_bytes = (
                secret_key.encode("utf-8")
                if isinstance(secret_key, str)
                else secret_key
            )
            priv, pub = self._load_key(
                key_bytes,
                (ec.EllipticCurvePrivateKey,),
                (ec.EllipticCurvePublicKey,),
                curve="secp384r1",
            )
            if priv is not None:
                self._secret = priv
                self._public_key = priv.public_key()
                return
            if pub is not None:
                self._secret = None
                self._public_key = pub
                return

            raise JamPASETOInvalidSecp384r1Key(
                message="Invalid EC key for v3.public (expect P-384 PEM/DER or key object)"
            )

    def _encode_public(
        self,
        header: str,
        payload: bytes,
        footer: bytes,
        implicit_assertion: bytes,
    ) -> bytes:
        """Encode a 'public' token."""
        if not isinstance(self._secret, ec.EllipticCurvePrivateKey):
            raise JamPASETOInvalidSecp384r1Key(
                message="Private EC P-384 key required for v3.public signing"
            )
        header_b = header.encode("ascii")
        public_numbers = self._public_key.public_numbers()
        compressed_public = bytes(
            [2 + (public_numbers.y & 1)]
        ) + public_numbers.x.to_bytes(48, "big")
        pre_auth = __pae__(
            [compressed_public, header_b, payload, footer, implicit_assertion]
        )

        der_sig = self._secret.sign(pre_auth, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der_sig)
        r_bytes = int.to_bytes(r, 48, "big")
        s_bytes = int.to_bytes(s, 48, "big")
        raw_sig = r_bytes + s_bytes  # 96 bytes

        token = header_b + base64url_encode(payload + raw_sig)
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
        header, payload_part, footer_part = self._parse_token(token, "public")
        decoded = base64url_decode(payload_part)

        if len(decoded) < 96:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid token body (too short for signature)"
            )

        payload = decoded[:-96]
        raw_sig = decoded[-96:]
        r = int.from_bytes(raw_sig[:48], "big")
        s = int.from_bytes(raw_sig[48:], "big")
        der_sig = encode_dss_signature(r, s)

        footer_decoded = base64url_decode(footer_part) if footer_part else b""
        if not self._public_key:
            raise JamPASETOInvalidSecp384r1Key(
                message="Public key required for v3.public verification"
            )
        public_numbers = self._public_key.public_numbers()
        compressed_public = bytes(
            [2 + (public_numbers.y & 1)]
        ) + public_numbers.x.to_bytes(48, "big")
        pre_auth = __pae__(
            [
                compressed_public,
                header,
                payload,
                footer_decoded,
                implicit_assertion,
            ]
        )

        try:
            self._public_key.verify(
                der_sig, pre_auth, ec.ECDSA(hashes.SHA384())
            )
        except InvalidSignature:
            raise JamPASETOInvalidTokenFormat(message="Invalid signature")

        return (
            serializer.loads(payload),
            self._decode_footer(footer_decoded, serializer),
        )
