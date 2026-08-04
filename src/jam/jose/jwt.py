# -*- coding: utf-8 -*-

import base64
import json
import logging
import time
from typing import TYPE_CHECKING, Any
import uuid

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamConfigurationError,
    JamJWTExpired,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamJWTNotYetValid,
    JamJWTUnsupportedAlgorithm,
)
from jam.exceptions.jose import (
    JamInvalidKeyTypeError,
    JamJWSVerificationError,
)
from jam.jose.__algorithms__ import (
    SUPPORTED_ALGORITHMS,
    SUPPORTED_ENC_ALGORITHMS,
    BaseAlgorithm,
    KeyLike,
    create_algorithm,
)
from jam.jose.__base__ import BaseJWT
from jam.jose.jwe import JWE
from jam.jose.jws import JWS
from jam.lists import BaseList, build_list
from jam.utils.config_maker import __key_loader__
from jam.utils.config_meta import ConfigMeta


logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from jam.jose.jwk import JWK


class JWT(BaseJWT, metaclass=ConfigMeta):
    """JWT (JSON Web Token) implementation - RFC 7519.

    Supports JWS (signed), JWE (encrypted), and JWS+JWE (sign then encrypt) tokens.
    """

    _CONFIG_POINTER = "jam.jose.jwt"
    JWS = JWS
    JWE = JWE
    _SUPPORTED_ALGORITHMS = SUPPORTED_ALGORITHMS

    def __init__(
        self,
        alg: str | None = None,
        enc: str | None = None,
        secret_key: str | bytes | KeyLike | "JWK" | None = None,
        password: str | bytes | None = None,
        list: dict[str, Any] | BaseList | None = None,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        jws: JWS | None = None,
        jwe: JWE | None = None,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize JWT instance.

        Args:
            alg (str | None): JWT algorithm name for signing (JWS). Used if jws is not provided.
            enc (str | None): JWE content encryption algorithm. If provided, creates encrypted JWT.
            secret_key (str | bytes | KeyLike | JWK | None): Key for signing/encryption.
            password (str | bytes | None): Password for encrypted private keys.
            list (dict[str, Any] | BaseList | None): List config or list instance for token storage.
            serializer (BaseEncoder | type[BaseEncoder]): JSON encoder/decoder.
            jws (JWS | None): Pre-built JWS instance. If provided, alg is ignored.
            jwe (JWE | None): Pre-built JWE instance. If provided, enc and secret_key are ignored.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.jose.jwt".

        Raises:
            ValueError: If neither alg/enc provided and no jws/jwe provided.
            ValueError: If both alg and jws are provided.
            ValueError: If both enc and jwe are provided.
            JamJWTUnsupportedAlgorithm: If algorithm is not supported.
        """
        self._serializer = serializer

        self.jws: JWS | None = None
        self.jwe: JWE | None = None
        self._alg: str | None = None
        self._enc: str | None = None

        if jws is not None:
            if alg is not None:
                raise JamConfigurationError(
                    message="Cannot specify both 'alg' and 'jws'. Use either 'jws' or 'alg'.",
                    error_code="configuration.jwt.conflicting_jws",
                )
            self.jws = jws
            self._alg = jws._alg
            self._key = self._normalize_key(secret_key)
            self._password = self._normalize_password(password)
            self._algorithm: BaseAlgorithm | None = None
        elif alg:
            if not enc:
                self._validate_algorithm(alg.upper())
            self._alg = alg.upper()
            self._key = self._normalize_key(secret_key)
            self._password = self._normalize_password(password)
            self._algorithm: BaseAlgorithm | None = None
            self.jws = self._build_jws()
        else:
            self.jws = None
            self._alg = None
            self._key = None
            self._password = None
            self._algorithm = None

        if jwe is not None:
            if enc is not None:
                raise JamConfigurationError(
                    message="Cannot specify both 'enc' and 'jwe'. Use either 'jwe' or 'enc'.",
                    error_code="configuration.jwt.conflicting_jwe",
                )
            self.jwe = jwe
            self._enc = jwe._enc
        elif enc:
            self._enc = enc.upper()
            if self._key is None:
                self._key = self._normalize_key(secret_key)
                self._password = self._normalize_password(password)
            self._validate_enc_algorithm(self._enc)
            self.jwe = self._build_jwe()
        else:
            self.jwe = None
            self._enc = None

        if not self.jws and not self.jwe:
            raise JamConfigurationError(
                message="Either 'alg', 'enc', 'jws', or 'jwe' must be provided",
                error_code="configuration.jwt.no_algorithm",
            )

        self.list = build_list(list) if list else None

        logger.info(
            "Initialized JWT with alg=%s, enc=%s, has_jws=%s, has_jwe=%s",
            self._alg,
            self._enc,
            self.jws is not None,
            self.jwe is not None,
        )

    def _normalize_key(
        self, key: str | bytes | KeyLike | "JWK" | None
    ) -> KeyLike | None:
        """Normalize key to KeyLike.

        Args:
            key: Key in various formats.

        Returns:
            KeyLike or None.
        """
        from jam.jose.jwk import JWK as JWKClass

        if key is None:
            return None
        if isinstance(key, JWKClass):
            return key._to_keylike()
        if isinstance(key, str):
            key = __key_loader__(key)
            return key.encode() if key else key
        return key

    def _build_jws(self) -> JWS:
        alg = self._alg
        key = self._key
        if not alg or not key:
            raise JamConfigurationError(
                message="JWS requires 'alg' and 'key'",
                error_code="configuration.jwt.missing_jws_key",
            )

        return JWS(
            alg=alg,
            key=key,
            password=self._password,
        )

    def _build_jwe(self) -> JWE:
        enc = self._enc
        if not enc:
            raise JamConfigurationError(
                message="JWE requires 'enc' to be provided",
                error_code="configuration.jwt.missing_enc",
            )

        key = self._key
        key_type = self._detect_key_type(key)

        if key_type == "rsa":
            jwe_alg = "RSA-OAEP"
            enc_key = key
        elif key_type == "ec":
            jwe_alg = "ECDH-ES"
            enc_key = key
        elif key_type == "symmetric":
            if isinstance(key, bytes):
                key_bytes = key
            elif isinstance(key, str):
                key_bytes = key.encode("utf-8")
            else:
                raise JamInvalidKeyTypeError(
                    message="Symmetric JWE requires a bytes or str key"
                )
            key_len = len(key_bytes)
            jwe_alg = "A256KW" if key_len >= 32 else "A128KW"
            enc_key = self._derive_encryption_key(key_bytes)
        else:
            raise JamInvalidKeyTypeError(
                message=f"Unsupported key type for JWE: {key_type}"
            )

        if enc_key is None:
            raise JamInvalidKeyTypeError(
                message=f"Unsupported key type for JWE: {key_type}"
            )

        return self.JWE(
            alg=jwe_alg,
            enc=enc,
            key=enc_key,
            password=self._password,
            serializer=self._serializer,
        )

    def _detect_key_type(self, key: KeyLike | None) -> str:
        """Detect the type of key.

        Returns:
            'rsa', 'ec', or 'symmetric'.
        """
        if key is None:
            return "symmetric"

        try:
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            from cryptography.hazmat.primitives.serialization import (
                load_der_private_key,
                load_der_public_key,
                load_pem_private_key,
                load_pem_public_key,
                load_ssh_public_key,
            )

            if isinstance(key, rsa.RSAPrivateKey | rsa.RSAPublicKey):
                return "rsa"
            if isinstance(
                key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey
            ):
                return "ec"

            if isinstance(key, bytes):
                try:
                    loaded = load_pem_private_key(key, password=None)
                    if isinstance(
                        loaded, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
                    ):
                        return (
                            "rsa"
                            if isinstance(loaded, rsa.RSAPrivateKey)
                            else "ec"
                        )
                except (ValueError, TypeError):
                    pass

                try:
                    loaded = load_der_private_key(key, password=None)
                    if isinstance(
                        loaded, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
                    ):
                        return (
                            "rsa"
                            if isinstance(loaded, rsa.RSAPrivateKey)
                            else "ec"
                        )
                except (ValueError, TypeError):
                    pass

                try:
                    loaded = load_pem_public_key(key)
                    if isinstance(
                        loaded, rsa.RSAPublicKey | ec.EllipticCurvePublicKey
                    ):
                        return (
                            "rsa"
                            if isinstance(loaded, rsa.RSAPublicKey)
                            else "ec"
                        )
                except (ValueError, TypeError):
                    pass

                try:
                    loaded = load_der_public_key(key)
                    if isinstance(
                        loaded, rsa.RSAPublicKey | ec.EllipticCurvePublicKey
                    ):
                        return (
                            "rsa"
                            if isinstance(loaded, rsa.RSAPublicKey)
                            else "ec"
                        )
                except (ValueError, TypeError):
                    pass

                try:
                    loaded = load_ssh_public_key(key)
                    if isinstance(
                        loaded, rsa.RSAPublicKey | ec.EllipticCurvePublicKey
                    ):
                        return (
                            "rsa"
                            if isinstance(loaded, rsa.RSAPublicKey)
                            else "ec"
                        )
                except (ValueError, TypeError):
                    pass

        except ImportError:
            pass

        return "symmetric"

    def _derive_encryption_key(self, signing_key: bytes) -> bytes:
        """Derive encryption key from signing key using HKDF.

        Args:
            signing_key: The signing key.

        Returns:
            32-byte encryption key.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"jwe-encryption",
            info=b"encryption-key",
        ).derive(signing_key)

    def _validate_algorithm(self, alg: str) -> None:
        """Validate JWS algorithm."""
        if alg not in self._SUPPORTED_ALGORITHMS:
            raise JamJWTUnsupportedAlgorithm(
                details={
                    "algorithm": alg,
                    "supported_algorithms": self._SUPPORTED_ALGORITHMS,
                }
            )

    def _validate_enc_algorithm(self, enc: str) -> None:
        """Validate JWE encryption algorithm."""
        if enc not in SUPPORTED_ENC_ALGORITHMS:
            raise JamJWTUnsupportedAlgorithm(
                details={
                    "algorithm": enc,
                    "supported_algorithms": SUPPORTED_ENC_ALGORITHMS,
                }
            )

    def _normalize_password(self, password: str | bytes | None) -> bytes | None:
        """Normalize password to bytes."""
        if password is None:
            return None
        return password.encode() if isinstance(password, str) else password

    @property
    def _algo(self) -> BaseAlgorithm:
        """Get or create algorithm instance."""
        alg = self._alg
        key = self._key
        if self._algorithm is None:
            if not alg or not key:
                raise JamConfigurationError(
                    message="JWS requires 'alg' and 'key'",
                    error_code="configuration.jwt.missing_jws_key",
                )
            self._algorithm = create_algorithm(alg, key, self._password)
        return self._algorithm

    def _make_payload(
        self,
        iss: str | None,
        sub: str | None,
        aud: str | None,
        exp: int | None,
        nbf: int | None,
        jti: str | None,
        data: dict[str, Any] | None,
    ) -> dict[str, Any]:
        now = int(time.time())
        payload = {
            "jti": jti,
            "iat": now,
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "exp": now + exp if exp else None,
            "nbf": now + nbf if nbf is not None else None,
        }
        if data:
            payload.update(data)
        payload = {k: v for k, v in payload.items() if v is not None}
        return payload

    @property
    def jti(self) -> str:
        """The JWT ID."""
        return str(uuid.uuid4())

    def encode(
        self,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
        exp: int | None = None,
        nbf: int | None = None,
        jti: str | None = None,
        header: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> str:
        """Encode the JWT with the given expire, header, and payload (JWS).

        Args:
            exp (int | None): The expiration time in seconds.
            nbf (int | None): The not-before time in seconds.
            iss (str | None): The issuer.
            sub (str | None): The subject.
            aud (str | None): The audience.
            jti (str | None): The JWT ID. If None, auto-generated.
            header (dict[str, Any] | None): The header to include in the JWT.
            payload (dict[str, Any] | None): The payload to include in the JWT.

        Returns:
            str: The encoded JWT (JWS compact serialization).

        Raises:
            JamConfigurationError: If alg is not provided.
        """
        if not self.jws:
            raise JamConfigurationError(
                message="JWS not configured. Provide 'alg' parameter.",
                error_code="configuration.jwt.jws_not_configured",
            )

        if jti is None:
            jti = self.jti

        _base_header = {"alg": self._alg, "typ": "JWT"}
        if header:
            _base_header.update(header)
        _payload = self._make_payload(iss, sub, aud, exp, nbf, jti, payload)
        token = self.jws.sign(header=_base_header, data=_payload)

        if self.list and self.list.__list_type__ == "white":
            self.list.add(token)

        return token

    def decode(
        self,
        token: str,
        validate_claims: bool = True,
        check_list: bool = True,
    ) -> dict[str, Any]:
        """Decode the JWT and return the header and payload.

        Args:
            token: JWT token.
            validate_claims: Whether to validate exp/nbf claims. Defaults to True.
            check_list: Whether to check the token in the white/black list.
                Defaults to True.

        Returns:
            dict with 'header' and 'payload' keys (both dicts).

        Raises:
            JamConfigurationError: If alg is not provided.
            JamJWSVerificationError: If token has invalid type.
            JamJWTExpired: If token is expired.
            JamJWTNotYetValid: If token is not yet valid.
            JamJWTNotInWhiteList: If token is not in the white list.
            JamJWTInBlackList: If token is in the black list.
        """
        if not self.jws:
            raise JamConfigurationError(
                message="JWS not configured. Provide 'alg' parameter.",
                error_code="configuration.jwt.jws_not_configured",
            )

        if check_list and self.list:
            match self.list.__list_type__:
                case "white":
                    if not self.list.check(token):
                        raise JamJWTNotInWhiteList
                case "black":
                    if self.list.check(token):
                        raise JamJWTInBlackList
                case _:
                    raise JamConfigurationError(
                        message="Invalid JWT list type",
                        error_code="configuration.jwt.unknown_list_type",
                    )

        data = self.jws.verify(token, True)
        header = data["header"]
        if header.get("typ") != "JWT":
            raise JamJWSVerificationError(message="Invalid token type")
        payload = json.loads(data["payload"])

        if validate_claims:
            self._validate_claims(payload)

        return {
            "header": header,
            "payload": payload,
        }

    def _validate_claims(self, payload: dict[str, Any]) -> None:
        """Validate JWT standard claims.

        Args:
            payload: JWT payload dict.

        Raises:
            JamJWTExpired: If token is expired.
            JamJWTNotYetValid: If token is not yet valid.
        """
        now = int(time.time())

        if "exp" in payload:
            exp = payload["exp"]
            if isinstance(exp, int | float) and exp < now:
                raise JamJWTExpired(details={"exp": exp, "now": now})

        if "nbf" in payload:
            nbf = payload["nbf"]
            if isinstance(nbf, int | float) and nbf > now:
                raise JamJWTNotYetValid(details={"nbf": nbf, "now": now})

    def encrypt(
        self,
        plaintext: bytes | str | dict[str, Any],
        header: dict[str, Any] | None = None,
    ) -> str:
        """Encrypt payload using JWE.

        If both jws and jwe are configured, creates JWS+JWE (sign then encrypt):
        1. Create JWS compact serialization (sign)
        2. Use JWS result as plaintext for JWE (encrypt)

        Args:
            plaintext (bytes | str | dict[str, Any]): Data to encrypt. If dict, will be JSON encoded.
            header (dict[str, Any] | None): Additional JWE header.

        Returns:
            str: Encrypted JWT (JWE or JWS+JWE).

        Raises:
            JamConfigurationError: If jwe is not configured.
        """
        if not self.jwe:
            raise JamConfigurationError(
                message="JWE not configured. Provide 'enc' parameter.",
                error_code="configuration.jwt.jwe_not_configured",
            )

        if isinstance(plaintext, dict):
            payload_bytes = self._serializer.dumps(plaintext)
        elif isinstance(plaintext, str):
            payload_bytes = plaintext.encode("utf-8")
        else:
            payload_bytes = plaintext

        if self.jws and self.jwe:
            _base_header = {"alg": self._alg, "typ": "JWT"}
            if header:
                _base_header.update(header)
            jws_payload = self.jws.sign(header=_base_header, data=payload_bytes)
            return self.jwe.encrypt(jws_payload, header)
        else:
            return self.jwe.encrypt(payload_bytes, header)

    def decrypt(self, token: str) -> dict[str, Any] | bytes:
        """Decrypt JWE or JWS+JWE token.

        If token is JWS+JWE (sign then encrypt):
        1. Decrypt JWE to get JWS compact serialization
        2. Verify JWS to get original payload

        Args:
            token: Encrypted JWT token.

        Returns:
            dict[str, Any]: Decrypted payload.

        Raises:
            JamConfigurationError: If enc is not provided.
        """
        if not self.jwe:
            raise JamConfigurationError(
                message="JWE not configured. Provide 'enc' parameter.",
                error_code="configuration.jwt.jwe_not_configured",
            )

        plaintext = self.jwe.decrypt(token)

        if self.jws and self._alg:
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode("utf-8")

            decoded = self.jws.verify(plaintext, True)
            payload = decoded.get("payload")
            payload_str = (
                payload.decode("utf-8")
                if isinstance(payload, bytes)
                else payload
            )
            if not isinstance(payload_str, str):
                raise JamJWSVerificationError(
                    message="Invalid JWS payload in nested token.",
                )

            if "." in payload_str:
                inner_parts = payload_str.split(".")
                inner_header_b64 = inner_parts[0]
                inner_header = json.loads(
                    base64.urlsafe_b64decode(inner_header_b64 + "==").decode()
                )
                inner_alg = inner_header.get("alg")

                if inner_alg and inner_alg != self._alg:
                    temp_jws = JWS(
                        alg=inner_alg,
                        key=self.jws._key,
                        password=self.jws._password,
                    )
                    inner_decoded = temp_jws.verify(payload_str, True)
                else:
                    inner_decoded = self.jws.verify(payload_str, True)

                inner_payload = inner_decoded.get("payload")
                if isinstance(inner_payload, bytes | str):
                    return self._serializer.loads(inner_payload)
                raise JamJWSVerificationError(
                    message="Invalid inner JWS payload.",
                )

            return self._serializer.loads(payload_str)

        try:
            return self._serializer.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError):
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode("utf-8")
            return {"raw": plaintext}
