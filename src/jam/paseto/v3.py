# -*- coding: utf-8 -*-
# type: ignore

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamPASETOInvalidSecp384r1Key,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
)
from jam.paseto.__base__ import BasePASETO, KeyLoadMixin, LegacyAEADMixin
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
from jam.utils.config_maker import __key_loader__


class PASETOv3(LegacyAEADMixin, KeyLoadMixin, BasePASETO):
    """PASETO v3 factory."""

    _VERSION = "v3"

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
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        """Encode a 'public' token."""
        if not isinstance(self._secret, ec.EllipticCurvePrivateKey):
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

    def _decode_public(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[Any, Any]:
        """Decode a 'public' token."""
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

        return (
            serializer.loads(payload),
            self._decode_footer(footer_decoded, serializer),
        )
