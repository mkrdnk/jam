# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from jam.exceptions import JamJWKValidationError
from jam.exceptions.jose import JamJWKInvalidKeyTypeError
from jam.jose.__algorithms__ import KeyLike
from jam.jose.__base__ import BaseJWK, BaseJWKSet
from jam.jose.jws import JWS
from jam.jose.utils import __base64url_decode__


logger = logging.getLogger(__name__)


class JWKCommon(TypedDict, total=False):
    """Common JWK parameters shared across all key types - RFC 7517 Section 4."""

    kty: str
    """Key Type. Required. Identifies the cryptographic algorithm family."""

    use: Literal["sig", "enc"]
    """Public Key Use. Identifies the intended use of the public key."""

    key_ops: list[str]
    """Key Operations. Identifies the operations for which the key is intended."""

    alg: str
    """Algorithm. Identifies the algorithm intended for use with the key."""

    kid: str
    """Key ID. Unique identifier for the key."""

    x5u: str
    """X.509 URL. URI pointing to an X.509 public key certificate or chain."""

    x5c: str
    """X.509 Certificate Chain. Base64-encoded X.509 public key certificate chain."""

    x5t: str
    """X.509 Certificate Thumbprint. Base64-encoded SHA-1 thumbprint of the certificate."""

    x5t_S256: str
    """X.509 Certificate SHA-256 Thumbprint. Base64-encoded SHA-256 thumbprint."""


class JWKRSA(JWKCommon, total=False):
    """RSA Key - RFC 7517 Section 6.3.

    Represents an RSA public or private key.

    Example:
        >>> rsa_key: JWKRSA = {
        ...     "kty": "RSA",
        ...     "n": "0vx7agoebGcQSuu...",
        ...     "e": "AQAB",
        ... }
    """

    n: str
    """RSA modulus n. The modulus value for the RSA public key."""

    e: str
    """RSA exponent e. The exponent value for the RSA public key."""

    d: str
    """RSA private exponent d. Present only in private keys."""

    p: str
    """First prime p. First prime factor of n. Present only in private keys."""

    q: str
    """Second prime q. Second prime factor of n. Present only in private keys."""

    dp: str
    """First factor exponent. d mod (p-1). Present only in private keys."""

    dq: str
    """Second factor exponent. d mod (q-1). Present only in private keys."""

    qi: str
    """First CRT coefficient. q^(-1) mod p. Present only in private keys."""


class JWKEC(JWKCommon, total=False):
    """Elliptic Curve Key - RFC 7517 Section 6.2.

    Represents an elliptic curve public or private key.

    Example:
        >>> ec_key: JWKEC = {
        ...     "kty": "EC",
        ...     "crv": "P-256",
        ...     "x": "f83OJ3D2xF1Bg8v...",
        ...     "y": "x_FEzRu9m36HLN_t...",
        ... }
    """

    crv: Literal["P-256", "P-384", "P-521"]
    """Elliptic curve name. The curve on which the key is based."""

    x: str
    """EC x coordinate. The x coordinate of the elliptic curve point."""

    y: str
    """EC y coordinate. The y coordinate of the elliptic curve point."""

    d: str
    """EC private key value. The private key value. Present only in private keys."""


class JWKOct(JWKCommon, total=False):
    """Symmetric (Octet Sequence) Key - RFC 7517 Section 6.4.

    Represents a symmetric (secret) key.

    Example:
        >>> oct_key: JWKOct = {
        ...     "kty": "oct",
        ...     "k": "AyM32w-xOvmxxkBq...",
        ... }
    """

    k: str
    """Key value. The base64url-encoded symmetric key value."""


JWKDict = JWKRSA | JWKEC | JWKOct
"""Union type representing any valid JWK dict."""


class JWK(BaseJWK):
    """JSON Web Key - RFC 7517.

    Provides JWK validation and signing capabilities.

    Example:
        ```python
        >>> jwk = JWK.from_dict({"kty": "oct", "k": "your-secret-key"})
        >>> jwk.sign(b"data", "HS256")
        >>> jwk.verify(token)
        ```
    """

    _SUPPORTED_KEY_TYPES = frozenset({"RSA", "EC", "oct"})
    _SUPPORTED_CURVES = frozenset({"P-256", "P-384", "P-521"})
    _DEFAULT_ALG_MAP = {"RSA": "RS256", "EC": "ES256", "oct": "HS256"}

    def __init__(self, data: dict[str, Any]) -> None:
        """Initialize JWK.

        Args:
            data: Validated JWK dict.
        """
        self._data = data

    @staticmethod
    def validate(data: dict[str, Any]) -> JWK:
        """Validate and normalize JWK dict.

        Args:
            data: JWK dict to validate.

        Returns:
            JWK instance.

        Raises:
            JamJWKValidationError: If JWK is invalid.
        """
        if "kty" not in data:
            logger.warning("Rejected JWK without key type")
            raise JamJWKValidationError(
                message="Missing required 'kty' parameter"
            )

        kty = data["kty"]
        if kty not in JWK._SUPPORTED_KEY_TYPES:
            logger.warning("Rejected JWK with unsupported key type")
            raise JamJWKValidationError(
                message=f"Unsupported kty: {kty}",
                details={"supported": list(JWK._SUPPORTED_KEY_TYPES)},
            )

        if kty == "RSA":
            _validate_rsa(data)
        elif kty == "EC":
            _validate_ec(data)
        elif kty == "oct":
            _validate_oct(data)

        logger.debug("Validated JWK with key type=%s", kty)
        return JWK(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWK:
        """Create JWK from dict.

        Alias for JWK.validate().

        Args:
            data: JWK dict.

        Returns:
            JWK instance.
        """
        return cls.validate(data)

    def to_dict(self) -> dict[str, Any]:
        """Convert JWK to dict.

        Returns:
            JWK dict.
        """
        return self._data.copy()

    @property
    def kty(self) -> str:
        """Get key type.

        Returns:
            Key type (RSA, EC, oct).
        """
        return self._data.get("kty", "")

    @property
    def alg(self) -> str | None:
        """Get algorithm from JWK if set.

        Returns:
            Algorithm or None.
        """
        return self._data.get("alg")

    @property
    def kid(self) -> str | None:
        """Get key ID if set.

        Returns:
            Key ID or None.
        """
        return self._data.get("kid")

    def sign(self, data: bytes, alg: str | None = None) -> str:
        """Sign data using JWK.

        Args:
            data: Data to sign.
            alg: Algorithm to use. If None, uses default for kty.

        Returns:
            JWS compact serialization string.

        Raises:
            ValueError: If algorithm is not supported or key is invalid.
        """
        _alg = alg or self.alg or self._get_default_alg()
        key = self._to_keylike()
        jws = JWS(alg=_alg, key=key)
        logger.debug("Signing data with JWK using alg=%s", _alg)
        return jws.serialize_compact({"alg": _alg}, data)

    def verify(self, token: str, alg: str | None = None) -> dict[str, Any]:
        """Verify JWS token and return payload.

        Args:
            token: JWS compact serialization token.
            alg: Algorithm to use. If None, uses default for kty.

        Returns:
            dict with 'header' and 'payload' keys.

        Raises:
            ValueError: If signature is invalid.
        """
        _alg = alg or self.alg or self._get_default_alg()
        key = self._to_keylike()
        jws = JWS(alg=_alg, key=key)
        logger.debug("Verifying JWS with JWK using alg=%s", _alg)
        return jws.deserialize_compact(token)

    def _get_default_alg(self) -> str:
        """Get default algorithm for kty.

        Returns:
            Algorithm name.
        """
        return self._DEFAULT_ALG_MAP.get(self.kty, "HS256")

    def _to_keylike(self) -> KeyLike:
        """Convert JWK to KeyLike for use with JWS.

        Returns:
            KeyLike object.

        Raises:
            ValueError: If key cannot be converted.
        """
        kty = self.kty

        if kty == "oct":
            return __base64url_decode__(self._data["k"])

        if kty == "RSA":
            return self._rsa_to_pem()

        if kty == "EC":
            return self._ec_to_pem()

        raise JamJWKInvalidKeyTypeError(message=f"Unsupported key type: {kty}")

    def _rsa_to_pem(self) -> str:
        """Convert RSA JWK to PEM format.

        Returns:
            PEM encoded key string.

        Raises:
            ValueError: If required parameters are missing.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        n = int.from_bytes(__base64url_decode__(self._data["n"]), "big")
        e = int.from_bytes(__base64url_decode__(self._data["e"]), "big")

        if "d" in self._data:
            required_private = ["d", "p", "q", "dp", "dq", "qi"]
            missing = [p for p in required_private if p not in self._data]
            if missing:
                raise JamJWKValidationError(
                    message=f"Missing RSA private key parameters: {missing}. "
                    "RFC 7518 Section 6.3.2 requires all: d, p, q, dp, dq, qi"
                )

            d = int.from_bytes(__base64url_decode__(self._data["d"]), "big")
            p = int.from_bytes(__base64url_decode__(self._data["p"]), "big")
            q = int.from_bytes(__base64url_decode__(self._data["q"]), "big")
            dp = int.from_bytes(__base64url_decode__(self._data["dp"]), "big")
            dq = int.from_bytes(__base64url_decode__(self._data["dq"]), "big")
            qi = int.from_bytes(__base64url_decode__(self._data["qi"]), "big")

            private_numbers = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=dp,
                dmq1=dq,
                iqmp=qi,
                public_numbers=rsa.RSAPublicNumbers(n=n, e=e),
            )
            key = private_numbers.private_key()
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        else:
            public_numbers = rsa.RSAPublicNumbers(n=n, e=e)
            key = public_numbers.public_key()
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()

    def _ec_to_pem(self) -> str:
        """Convert EC JWK to PEM format.

        Returns:
            PEM encoded key string.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        x = int.from_bytes(__base64url_decode__(self._data["x"]), "big")
        y = int.from_bytes(__base64url_decode__(self._data["y"]), "big")

        curve_name = self._data["crv"]
        curve = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }[curve_name]

        public_key = ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=curve
        ).public_key()

        if "d" in self._data:
            d = int.from_bytes(__base64url_decode__(self._data["d"]), "big")
            private_key = ec.derive_private_key(d, curve)
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        else:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()


def _validate_rsa(jwk: dict[str, Any]) -> None:
    """Validate RSA JWK parameters."""
    required = ["n", "e"]
    missing = [p for p in required if p not in jwk]
    if missing:
        raise JamJWKValidationError(
            message=f"Missing RSA parameters: {missing}"
        )


def _validate_ec(jwk: dict[str, Any]) -> None:
    """Validate EC JWK parameters."""
    required = ["crv", "x", "y"]
    missing = [p for p in required if p not in jwk]
    if missing:
        raise JamJWKValidationError(message=f"Missing EC parameters: {missing}")

    if jwk["crv"] not in JWK._SUPPORTED_CURVES:
        raise JamJWKValidationError(
            message=f"Invalid EC curve: {jwk['crv']}",
            details={"supported": list(JWK._SUPPORTED_CURVES)},
        )


def _validate_oct(jwk: dict[str, Any]) -> None:
    """Validate symmetric (oct) JWK parameters."""
    if "k" not in jwk:
        raise JamJWKValidationError(
            message="Missing required 'k' parameter for symmetric key"
        )


class JWKSet(BaseJWKSet):
    """JWK Set - RFC 7517 Section 5.

    Represents a set of JWKs. Used to organize and filter collections of keys.

    Example:
        ```python
        >>> jwkset = JWKSet(keys=[rsa_key, ec_key])
        >>> jwkset.get_by_kid("my-key-id")
        >>> jwkset.filter(kty="RSA")
        ```
    """

    def __init__(self, keys: list[dict[str, Any]] | None = None):
        """Initialize JWKSet.

        Args:
            keys: List of JWK dicts.
        """
        self._keys = keys or []

    def get_by_kid(self, kid: str) -> dict[str, Any] | None:
        """Get JWK by key ID (kid).

        Args:
            kid: Key ID to search for.

        Returns:
            JWK dict if found, None otherwise.
        """
        for key in self._keys:
            if key.get("kid") == kid:
                return key
        return None

    def get_by_kty(self, kty: str) -> list[dict[str, Any]]:
        """Get all JWKs by key type.

        Args:
            kty: Key type (RSA, EC, oct).

        Returns:
            List of matching JWK dicts.
        """
        return [k for k in self._keys if k.get("kty") == kty]

    def filter(self, **criteria: Any) -> list[dict[str, Any]]:
        """Filter JWKs by criteria.

        Args:
            **criteria: Filter criteria (kty, use, alg, key_ops, kid).

        Returns:
            List of matching JWK dicts.
        """
        results = self._keys
        for attr, value in criteria.items():
            if value is None:
                continue
            results = [k for k in results if k.get(attr) == value]
        return results

    def to_dict(self) -> dict[str, Any]:
        """Convert JWKSet to dict.

        Returns:
            dict with "keys" key containing list of JWKs.
        """
        return {"keys": self._keys}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWKSet:
        """Create JWKSet from dict.

        Args:
            data: Dict with "keys" key.

        Returns:
            JWKSet instance.

        Raises:
            JamJWKValidationError: If data is invalid.
        """
        if "keys" not in data:
            raise JamJWKValidationError(message="Missing 'keys' in JWKSet")
        keys = data["keys"]
        if not isinstance(keys, list):
            raise JamJWKValidationError(message="'keys' must be a list")
        validated_keys = [JWK.validate(k) for k in keys]
        return cls(keys=[k.to_dict() for k in validated_keys])
