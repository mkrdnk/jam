# -*- coding: utf-8 -*-
# type: ignore

import hashlib
import hmac
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidPurpose,
    JamPASETOInvalidSecp384r1Key,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
)
from jam.paseto.__base__ import BasePASETO
from jam.paseto.utils import (
    __gen_hash__,
    __pae__,
    base64url_decode,
    base64url_encode,
)
from jam.utils.config_maker import __key_loader__


class PASETOv3(BasePASETO):
    """PASETO v3 factory."""

    _VERSION = "v3"

    def _set_key(self, secret_key: str | bytes) -> None:
        """Process the key.

        Args:
            secret_key (str | bytes): Private PEM or secret key.
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

        elif self._purpose == "public":
            if isinstance(secret_key, str):
                secret_key = __key_loader__(secret_key)
            if hasattr(secret_key, "sign") and isinstance(
                secret_key, ec.EllipticCurvePrivateKey
            ):
                if secret_key.curve.name != "secp384r1":
                    raise JamPASETOInvalidSecp384r1Key(
                        "PASETOv3.public requires P-384 (secp384r1) keys"
                    )
                self._secret = secret_key
                self._public_key = secret_key.public_key()
                return

            if hasattr(secret_key, "verify") and isinstance(
                secret_key, ec.EllipticCurvePublicKey
            ):
                if secret_key.curve.name != "secp384r1":
                    raise JamPASETOInvalidSecp384r1Key(
                        "PASETOv3.public requires P-384 (secp384r1) keys"
                    )
                self._secret = None
                self._public_key = secret_key
                return

            # bytes / PEM string -> try load PEM/DER
            if isinstance(secret_key, str):
                key_bytes = secret_key.encode("utf-8")
            else:
                key_bytes = secret_key

            # try private PEM/DER first
            try:
                priv = serialization.load_pem_private_key(
                    key_bytes, password=None
                )
                if (
                    not isinstance(priv, ec.EllipticCurvePrivateKey)
                    or priv.curve.name != "secp384r1"
                ):
                    raise JamPASETOInvalidSecp384r1Key(
                        message="Invalid ECDSA key type"
                    )
                self._secret = priv
                self._public_key = priv.public_key()
                return
            except Exception:
                try:
                    priv = serialization.load_der_private_key(
                        key_bytes, password=None
                    )
                    if (
                        isinstance(priv, ec.EllipticCurvePrivateKey)
                        and priv.curve.name == "secp384r1"
                    ):
                        self._secret = priv
                        self._public_key = priv.public_key()
                        return
                except Exception:
                    pass

            try:
                pub = serialization.load_pem_public_key(key_bytes)
                if (
                    not isinstance(pub, ec.EllipticCurvePublicKey)
                    or pub.curve.name != "secp384r1"
                ):
                    raise JamPASETOInvalidSecp384r1Key(
                        message="Invalid ECDSA public key type"
                    )
                self._secret = None
                self._public_key = pub
                return
            except Exception:
                try:
                    pub = serialization.load_der_public_key(key_bytes)
                    if (
                        isinstance(pub, ec.EllipticCurvePublicKey)
                        and pub.curve.name == "secp384r1"
                    ):
                        self._secret = None
                        self._public_key = pub
                        return
                except Exception:
                    pass

            raise JamPASETOInvalidSecp384r1Key(
                message="Invalid EC key for v3.public (expect P-384 PEM/DER or key object)"
            )

    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | bytes | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> str:
        """Encode PASETO.

        Args:
            payload (dict[str, Any]): Token payload
            footer (dict[str, Any] | None): Footer if needed
            serializer (type[BaseEncoder] | BaseEncoder): JSON Serializer

        Returns:
            str: Token
        """
        header = f"{self._VERSION}.{self._purpose}."
        payload_bytes = serializer.dumps(payload)
        # normalize footer: if dict or list -> dumps, if str -> encode, if bytes -> as is, if None -> b""
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
            serializer (type[BaseEncoder] | BaseEncoder]): JSON serializer

        Returns:
            Payload and dict
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
        nonce = secrets.token_bytes(32)
        pl = __gen_hash__(nonce, payload, 32)

        hkdf_params = {
            "algorithm": hashes.SHA384(),
            "length": 32,
            "salt": pl[0:16],
        }
        ek = HKDF(info=b"paseto-encryption-key", **hkdf_params).derive(
            self._secret
        )
        ak = HKDF(info=b"paseto-auth-key-for-aead", **hkdf_params).derive(
            self._secret
        )

        ciphertext = self._encrypt(ek, pl[16:], payload)
        pre_auth = __pae__([header_b, pl, ciphertext, footer or b""])
        tag = hmac.new(ak, pre_auth, hashlib.sha384).digest()

        body = pl + ciphertext + tag
        token = header_b + base64url_encode(body)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_local(self, token: str, serializer: BaseEncoder):
        parts = token.encode("utf-8").split(b".")
        if len(parts) < 3:
            raise ValueError("Invalid token format")
        header = b".".join(parts[:2]) + b"."
        if header != b"v3.local.":
            raise ValueError("Invalid header")
        payload_part = parts[2]
        footer_part = parts[3] if len(parts) > 3 else b""
        decoded = base64url_decode(payload_part)
        if len(decoded) < 80:
            raise JamPASETOInvalidTokenFormat(message="Invalid payload size")

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
        ek = HKDF(info=b"paseto-encryption-key", **hkdf_params).derive(
            self._secret
        )
        ak = HKDF(info=b"paseto-auth-key-for-aead", **hkdf_params).derive(
            self._secret
        )

        pre_auth = __pae__([header, pl, ciphertext, footer_decoded])
        expected_tag = hmac.new(ak, pre_auth, hashlib.sha384).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise JamPASETOInvalidTokenFormat(
                message="Invalid authentication tag"
            )

        payload_bytes = self._decrypt(ek, pl[16:], ciphertext)
        payload = serializer.loads(payload_bytes)

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
            self._secret, ec.EllipticCurvePrivateKey
        ):
            raise JamPASETOInvalidSecp384r1Key(
                message="Private EC P-384 key required for v3.public signing"
            )
        header_b = header.encode("ascii")
        pre_auth = __pae__([header_b, payload, footer or b""])

        der_sig = self._secret.sign(pre_auth, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der_sig)
        r_bytes = int.to_bytes(r, 48, "big")
        s_bytes = int.to_bytes(s, 48, "big")
        raw_sig = r_bytes + s_bytes  # 96 bytes

        token = header_b + base64url_encode(payload + raw_sig)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_public(self, token: str, serializer: BaseEncoder):
        parts = token.encode("utf-8").split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat(message="Invalid token format")
        header = b".".join(parts[:2]) + b"."
        if header != b"v3.public.":
            raise JamPASETOInvalidTokenFormat(message="Invalid header")

        payload_part = parts[2]
        footer_part = parts[3] if len(parts) > 3 else b""
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
        pre_auth = __pae__([header, payload, footer_decoded])

        if not self._public_key:
            raise JamPASETOInvalidSecp384r1Key(
                message="Public key required for v3.public verification"
            )

        try:
            self._public_key.verify(
                der_sig, pre_auth, ec.ECDSA(hashes.SHA384())
            )
        except InvalidSignature:
            raise JamPASETOInvalidTokenFormat(message="Invalid signature")

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
