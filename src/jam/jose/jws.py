# -*- coding: utf-8 -*-

import json
from typing import TYPE_CHECKING, Any

from jam.exceptions import JamJWTUnsupportedAlgorithm
from jam.exceptions.jose import (
    JamJWSVerificationError,
)
from jam.jose.__algorithms__ import (
    SUPPORTED_ALGORITHMS,
    KeyLike,
    create_algorithm,
)
from jam.jose.__base__ import BaseJWS
from jam.jose.utils import __base64url_decode__, __base64url_encode__
from jam.utils.config_maker import __key_loader__
from jam.utils.config_meta import ConfigMeta


if TYPE_CHECKING:
    from jam.jose.jwk import JWK


class JWS(BaseJWS, metaclass=ConfigMeta):
    """JWS (JSON Web Signature) implementation - RFC 7515."""

    _CONFIG_POINTER = "jam.jose.jws"
    _SUPPORTED_ALGORITHMS = SUPPORTED_ALGORITHMS

    def __init__(
        self,
        alg: str,
        key: KeyLike | "JWK",
        password: bytes | None = None,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize the JWS object.

        Args:
            alg (str): Algorithm name
            key (KeyLike | JWK): Key to use for signing/verifying
            password (bytes | None): Password for encrypted private keys
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.jose.jws".
        """
        from jam.jose.jwk import JWK as JWKClass

        self._alg = alg.upper()
        self._validate_algorithm(self._alg)

        if isinstance(key, str):
            key = __key_loader__(key)

        if isinstance(key, JWKClass):
            key = key._to_keylike()

        self._key = key
        self._password = password

        self._algorithm = create_algorithm(
            alg=self._alg,
            secret=key,
            password=password,
        )

    def _validate_algorithm(self, alg: str) -> None:
        """Validate algorithm name.

        Args:
            alg (str): Algorithm name

        Raises:
            JamJWTUnsupportedAlgorithm: If algorithm is not supported
        """
        if alg not in self._SUPPORTED_ALGORITHMS:
            raise JamJWTUnsupportedAlgorithm(
                details={
                    "algorithm": alg,
                    "supported_algorithms": self._SUPPORTED_ALGORITHMS,
                }
            )

    def serialize_compact(
        self,
        protected: dict[str, Any],
        payload: bytes | str | dict[str, Any],
    ) -> str:
        """Create JWS Compact Serialization.

        Args:
            protected (dict[str, Any]): Protected header (must include 'alg').
            payload (bytes | str): Payload to sign. If dict, will be JSON encoded.

        Returns:
            str: JWS in compact serialization format:
                 BASE64URL(protected).BASE64URL(payload).BASE64URL(signature)
        """
        _protected = {"alg": self._alg, **protected}

        protected_b64 = __base64url_encode__(
            json.dumps(_protected, separators=(",", ":")).encode()
        )

        if isinstance(payload, dict):
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        elif isinstance(payload, str):
            payload_bytes = payload.encode()
        else:
            payload_bytes = payload
        payload_b64 = __base64url_encode__(payload_bytes)

        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature_b64 = self._algorithm.sign(signing_input)

        return f"{protected_b64}.{payload_b64}.{signature_b64}"

    def deserialize_compact(
        self,
        s: str,
        validate: bool = True,
    ) -> dict[str, Any]:
        """Parse JWS Compact Serialization.

        Args:
            s (str): JWS in compact serialization format.
            validate (bool): Whether to validate signature. Defaults to True.

        Returns:
            dict[str, Any]: Parsed JWS with keys:
                - header: Protected header dict
                - payload: Decoded payload bytes
                - signature: Raw signature bytes

        Raises:
            JamJWSVerificationError: If validation fails or format is invalid.
        """
        try:
            protected_b64, payload_b64, signature_b64 = s.split(".")
        except ValueError:
            raise JamJWSVerificationError(
                details={"reason": "invalid_jws_format"}
            )

        header = json.loads(__base64url_decode__(protected_b64).decode())

        if "crit" in header:
            registered = {"alg", "typ", "kid", "x5u", "x5t", "cty", "crit"}
            unknown = [k for k in header["crit"] if k not in registered]
            if unknown:
                raise JamJWSVerificationError(
                    details={
                        "reason": "unknown_critical_header",
                        "unknown": unknown,
                    }
                )

        header_alg = header.get("alg")
        if header_alg != self._alg:
            raise JamJWSVerificationError(
                details={
                    "reason": "algorithm_mismatch",
                    "expected": self._alg,
                    "got": header_alg,
                }
            )

        signature = __base64url_decode__(signature_b64)

        if validate:
            signing_input = f"{protected_b64}.{payload_b64}".encode()
            try:
                self._algorithm.verify(signature, signing_input, self._key)
            except ValueError:
                raise JamJWSVerificationError(
                    details={"reason": "signature_verification_failed"}
                )

        return {
            "header": header,
            "payload": __base64url_decode__(payload_b64),
            "signature": signature,
        }

    def sign(
        self,
        header: dict[str, Any],
        data: bytes | str | dict[str, Any],
    ) -> str:
        """Sign data and return JWS compact serialization.

        Args:
            header: Protected header (alg will be added automatically).
            data: Data to sign. If dict, will be JSON encoded.

        Returns:
            JWS compact serialization string.
        """
        return self.serialize_compact(protected=header, payload=data)

    def verify(self, token: str, validate: bool = True) -> dict[str, Any]:
        """Verify and parse JWS token.

        Args:
            token: JWS compact serialization string.
            validate: Whether to validate signature.

        Returns:
            dict with 'header', 'payload', 'signature' keys.
        """
        return self.deserialize_compact(s=token, validate=validate)
