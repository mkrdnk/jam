# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions.jose import (
    JamJWEDecryptionError,
    JamJWEEncryptionError,
    JamJWEInvalidFormatError,
)
from jam.jose.__algorithms__ import (
    SUPPORTED_ENC_ALGORITHMS,
    SUPPORTED_KEY_ALGORITHMS,
    KeyLike,
    create_enc_algorithm,
    create_key_algorithm,
)
from jam.jose.__base__ import BaseJWE
from jam.utils.config_meta import ConfigMeta


if TYPE_CHECKING:
    from jam.jose.jwk import JWK
from jam.jose.utils import __base64url_decode__, __base64url_encode__
from jam.logger import BaseLogger, logger


class JWE(BaseJWE, metaclass=ConfigMeta):
    """JWE (JSON Web Encryption) implementation - RFC 7516.

    Provides encryption and decryption of data using JWK keys.

    Example:
        ```python
        >>> jwk = JWK.from_dict({"kty": "oct", "k": "your-secret-key"})
        >>> jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=jwk)
        >>> token = jwe.encrypt("secret data")
        >>> plaintext = jwe.decrypt(token)
        ```
    """

    _CONFIG_POINTER = "jam.jose.jwe"

    def __init__(
        self,
        alg: str,
        enc: str,
        key: KeyLike | JWK,
        password: bytes | None = None,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        logger: BaseLogger = logger,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize JWE.

        Args:
            alg: Key management algorithm (e.g., "A128KW", "RSA-OAEP").
            enc: Content encryption algorithm (e.g., "A128CBC-HS256", "A256GCM").
            key: Key for encryption/decryption. Can be KeyLike or JWK.
            password: Password for encrypted private keys.
            serializer: Encoder for serializing/deserializing JSON data.
            logger: Logger instance.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.jose.jwe".
        """
        from jam.jose.jwk import JWK as JWKClass

        self._alg = alg.upper()
        self._enc = enc.upper()
        if isinstance(key, JWKClass):
            key = key._to_keylike()
        self._key = key
        self._password = password
        self._serializer = serializer
        self._logger = logger

        if self._alg not in SUPPORTED_KEY_ALGORITHMS:
            raise JamJWEEncryptionError(
                message=f"Unsupported key algorithm: {self._alg}",
                details={"supported": list(SUPPORTED_KEY_ALGORITHMS)},
            )

        if self._enc not in SUPPORTED_ENC_ALGORITHMS:
            raise JamJWEEncryptionError(
                message=f"Unsupported content encryption algorithm: {self._enc}",
                details={"supported": list(SUPPORTED_ENC_ALGORITHMS)},
            )

        if isinstance(key, JWKClass):
            self._key = key._to_keylike()

    def encrypt(
        self,
        plaintext: bytes | str | dict[str, Any],
        header: dict[str, Any] | None = None,
    ) -> str:
        """Encrypt plaintext.

        Args:
            plaintext: Data to encrypt. If str, will be encoded to UTF-8.
                If dict, will be serialized using self._serializer.
            header: Additional JWE header.

        Returns:
            JWE compact serialization string.

        Raises:
            JamJWEEncryptionError: If encryption fails.
        """
        try:
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode("utf-8")
            elif isinstance(plaintext, dict):
                plaintext_bytes = self._serializer.dumps(plaintext)
            else:
                plaintext_bytes = plaintext

            merged_header = {"alg": self._alg, "enc": self._enc}
            if header:
                merged_header.update(header)

            enc_alg = create_enc_algorithm(self._enc, self._logger)
            key_alg = create_key_algorithm(
                self._alg, self._key, self._password, self._logger
            )

            iv = os.urandom(enc_alg.get_iv_length())
            cek = os.urandom(enc_alg.get_key_length())

            encrypted_key, header_updates = key_alg.wrap_key(cek)
            merged_header.update(header_updates)

            protected = json.dumps(
                merged_header, separators=(",", ":")
            ).encode()
            protected_b64 = __base64url_encode__(protected)

            aad = protected_b64.encode()
            ciphertext, tag = enc_alg.encrypt(plaintext_bytes, iv, aad, cek)

            iv_b64 = __base64url_encode__(iv)
            ciphertext_b64 = __base64url_encode__(ciphertext)
            tag_b64 = __base64url_encode__(tag)

            return (
                f"{protected_b64}.{__base64url_encode__(encrypted_key)}."
                f"{iv_b64}.{ciphertext_b64}.{tag_b64}"
            )
        except Exception as e:
            self._logger.error("JWE encryption failed: %s", e, exc_info=True)
            raise JamJWEEncryptionError(
                message=f"JWE encryption failed: {e}"
            ) from e

    def decrypt(self, token: str) -> bytes:
        """Decrypt JWE token.

        Args:
            token: JWE compact serialization string.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            JamJWEDecryptionError: If decryption fails.
        """
        try:
            parts = token.split(".")
            if len(parts) != 5:
                raise JamJWEInvalidFormatError(
                    message="Invalid JWE compact serialization format"
                )

            (
                protected_b64,
                encrypted_key_b64,
                iv_b64,
                ciphertext_b64,
                tag_b64,
            ) = parts

            protected = json.loads(__base64url_decode__(protected_b64).decode())

            alg = protected.get("alg", self._alg)
            enc = protected.get("enc", self._enc)

            enc_alg = create_enc_algorithm(enc, self._logger)
            key_alg = create_key_algorithm(
                alg, self._key, self._password, self._logger
            )

            encrypted_key = __base64url_decode__(encrypted_key_b64)
            cek = key_alg.unwrap_key(encrypted_key, protected)

            iv = __base64url_decode__(iv_b64)
            ciphertext = __base64url_decode__(ciphertext_b64)
            tag = __base64url_decode__(tag_b64)

            aad = protected_b64.encode()
            plaintext = enc_alg.decrypt(ciphertext, iv, tag, aad, cek)

            return plaintext
        except Exception as e:
            self._logger.error("JWE decryption failed: %s", e, exc_info=True)
            raise JamJWEDecryptionError(
                message=f"JWE decryption failed: {e}"
            ) from e
