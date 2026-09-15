# -*- coding: utf-8 -*-

from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import hmac
import logging
import os
from typing import Any, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from jam.exceptions.jose import (
    JamAlgorithmError,
    JamInvalidKeyTypeError,
    JamInvalidPaddingError,
    JamJWSInvalidFormatError,
    JamJWSSigningError,
    JamJWSValidationError,
    JamJWSVerificationError,
)
from jam.jose.utils import __base64url_decode__, __base64url_encode__


logger = logging.getLogger(__name__)


KeyLike = Union[
    str,
    bytes,
    rsa.RSAPrivateKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePrivateKey,
    ec.EllipticCurvePublicKey,
]


class BaseAlgorithm(ABC):
    """Base class for JWT signing algorithms."""

    def __init__(
        self,
        alg: str,
        secret: KeyLike,
        password: bytes | None,
    ) -> None:
        """Initialize algorithm.

        Args:
            alg (str): Algorithm name
            secret (KeyLike): Secret key
            password (bytes | None): Password for private key
        """
        self.alg = alg
        self._secret = secret
        self._password = password

    @abstractmethod
    def sign(self, data: bytes) -> str:
        """Sign data.

        Args:
            data (bytes): Data to sign

        Returns:
            str: Base64url encoded signature
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, sig: bytes, data: bytes, key: KeyLike) -> None:
        """Verify signature.

        Args:
            sig (bytes): Signature to verify
            data (bytes): Data that was signed
            key (KeyLike): Key for verification

        Raises:
            ValueError: If signature is invalid
        """
        raise NotImplementedError

    def _load_key_data(self, data: KeyLike) -> bytes:
        """Load key data from string or bytes.

        Args:
            data (str | bytes): Key data or path to key file

        Returns:
            bytes: Key bytes
        """
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            from pathlib import Path

            path = Path(data)
            try:
                is_file = path.is_file()
            except OSError:
                is_file = False
            return path.read_bytes() if is_file else data.encode()
        if isinstance(data, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
            data = data.public_key()
        return data.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _load_private_key(
        self, key_bytes: bytes | None, key_obj: Any | None
    ) -> Any:
        """Load private key from bytes or use key object.

        Args:
            key_bytes (bytes | None): Key bytes
            key_obj (Any | None): Key object

        Returns:
            Any: Private key object

        Raises:
            ValueError: If key cannot be loaded
        """
        if key_bytes is None:
            return key_obj

        try:
            return serialization.load_pem_private_key(
                key_bytes, password=self._password
            )
        except ValueError as e:
            logger.error(
                f"Failed to load private key: {e}",
                exc_info=True,
            )
            raise JamJWSInvalidFormatError(
                message=f"Invalid private key format: {e}"
            ) from e

    def _load_public_key_auto(self, key: KeyLike) -> Any:
        """Load public key automatically from various formats.

        Args:
            key (KeyLike): Key in various formats

        Returns:
            Any: Public key object

        Raises:
            ValueError: If key cannot be loaded
        """
        if hasattr(key, "public_key"):
            return key.public_key()  # type: ignore

        key_bytes = (
            self._load_key_data(key) if isinstance(key, str | bytes) else None
        )
        if not key_bytes:
            return key

        try:
            return serialization.load_pem_public_key(key_bytes)
        except ValueError:
            try:
                priv = serialization.load_pem_private_key(
                    key_bytes, password=self._password
                )
                logger.debug(
                    "Extracted public key from private PEM automatically."
                )
                return priv.public_key()
            except ValueError as e:
                logger.error(
                    f"Failed to load public key: {e}",
                    exc_info=True,
                )
                raise JamJWSInvalidFormatError(
                    message=f"Invalid key format: {e}"
                ) from e


class HSAlgorithm(BaseAlgorithm):
    """HMAC-based algorithms (HS256, HS384, HS512)."""

    def sign(self, data: bytes) -> str:
        """Sign data using HMAC.

        Args:
            data (bytes): Data to sign

        Returns:
            str: Base64url encoded signature
        """
        logger.debug("Signing with %s", self.alg)
        key = (
            self._secret.encode()
            if isinstance(self._secret, str)
            else self._secret
        )
        if not isinstance(key, bytes):
            raise JamInvalidKeyTypeError(
                message=f"Invalid key type for {self.alg}: expected str or bytes"
            )

        digest = getattr(hashlib, f"sha{self.alg[2:]}")
        sig = hmac.new(key, data, digest).digest()
        return __base64url_encode__(sig)

    def verify(self, sig: bytes, data: bytes, key: KeyLike) -> None:
        """Verify HMAC signature.

        Args:
            sig (bytes): Signature to verify
            data (bytes): Data that was signed
            key (KeyLike): Key for verification

        Raises:
            JamJWSVerificationError: If signature is invalid
        """
        logger.debug("Verifying %s signature", self.alg)
        k = key.encode() if isinstance(key, str) else key
        if not isinstance(k, bytes):
            raise JamInvalidKeyTypeError(
                message=f"Invalid key type for {self.alg}: expected str or bytes"
            )

        digest = getattr(hashlib, f"sha{self.alg[2:]}")
        expected = hmac.new(k, data, digest).digest()
        if not hmac.compare_digest(sig, expected):
            logger.warning("HMAC signature verification failed")
            raise JamJWSVerificationError(message="Invalid HMAC signature")


class RSAlgorithm(BaseAlgorithm):
    """RSA PKCS1v15 algorithms (RS256, RS384, RS512)."""

    def _get_private_key(self) -> Any:
        """Get private key for signing.

        Returns:
            Any: Private key object

        Raises:
            ValueError: If key cannot be loaded
        """
        key_bytes = (
            self._load_key_data(self._secret)
            if isinstance(self._secret, str | bytes)
            else None
        )
        return self._load_private_key(key_bytes, self._secret)

    def sign(self, data: bytes) -> str:
        """Sign data using RSA PKCS1v15.

        Args:
            data (bytes): Data to sign

        Returns:
            str: Base64url encoded signature
        """
        logger.debug("Signing with %s", self.alg)
        try:
            private_key = self._get_private_key()
            hash_alg = getattr(hashes, f"SHA{self.alg[2:]}")()
            sig = private_key.sign(data, padding.PKCS1v15(), hash_alg)
            return __base64url_encode__(sig)
        except Exception as e:
            logger.error(
                f"Failed to sign with {self.alg}: {e}",
                exc_info=True,
            )
            raise JamJWSSigningError(message=f"Signing failed: {e}") from e

    def verify(self, sig: bytes, data: bytes, key: KeyLike) -> None:
        """Verify RSA PKCS1v15 signature.

        Args:
            sig (bytes): Signature to verify
            data (bytes): Data that was signed
            key (KeyLike): Key for verification

        Raises:
            JamJWSVerificationError: If signature is invalid
        """
        logger.debug("Verifying %s signature", self.alg)
        try:
            pub_key = self._load_public_key_auto(key)
            hash_alg = getattr(hashes, f"SHA{self.alg[2:]}")()
            pub_key.verify(sig, data, padding.PKCS1v15(), hash_alg)
        except Exception as e:
            logger.warning(
                f"RSA signature verification failed: {e}",
                exc_info=True,
            )
            raise JamJWSVerificationError(
                message=f"Invalid RSA signature: {e}"
            ) from e


class ESAlgorithm(BaseAlgorithm):
    """ECDSA algorithms (ES256, ES384, ES512)."""

    _CURVE_MAP = {
        "ES256": (ec.SECP256R1(), hashes.SHA256()),
        "ES384": (ec.SECP384R1(), hashes.SHA384()),
        "ES512": (ec.SECP521R1(), hashes.SHA512()),
    }

    def _get_private_key(self) -> Any:
        """Get private key for signing.

        Returns:
            Any: Private key object

        Raises:
            ValueError: If key cannot be loaded
        """
        key_bytes = (
            self._load_key_data(self._secret)
            if isinstance(self._secret, str | bytes)
            else None
        )
        return self._load_private_key(key_bytes, self._secret)

    def sign(self, data: bytes) -> str:
        """Sign data using ECDSA.

        Args:
            data (bytes): Data to sign

        Returns:
            str: Base64url encoded signature
        """
        logger.debug("Signing with %s", self.alg)
        try:
            private_key = self._get_private_key()
            _, hash_alg = self._CURVE_MAP[self.alg]
            der = private_key.sign(data, ec.ECDSA(hash_alg))
            r, s = decode_dss_signature(der)
            n = (private_key.curve.key_size + 7) // 8
            raw = r.to_bytes(n, "big") + s.to_bytes(n, "big")
            return __base64url_encode__(raw)
        except Exception as e:
            logger.error(
                f"Failed to sign with {self.alg}: {e}",
                exc_info=True,
            )
            raise JamJWSSigningError(message=f"Signing failed: {e}") from e

    def verify(self, sig: bytes, data: bytes, key: KeyLike) -> None:
        """Verify ECDSA signature.

        Args:
            sig (bytes): Signature to verify
            data (bytes): Data that was signed
            key (KeyLike): Key for verification

        Raises:
            JamJWSVerificationError: If signature is invalid
        """
        logger.debug("Verifying %s signature", self.alg)
        try:
            pub_key = self._load_public_key_auto(key)
            _, hash_alg = self._CURVE_MAP[self.alg]
            n = (pub_key.curve.key_size + 7) // 8
            if len(sig) != 2 * n:
                raise JamJWSVerificationError(
                    message=f"Invalid signature length: expected {2 * n}, got {len(sig)}"
                )
            r, s = (
                int.from_bytes(sig[:n], "big"),
                int.from_bytes(sig[n:], "big"),
            )
            der = encode_dss_signature(r, s)
            pub_key.verify(der, data, ec.ECDSA(hash_alg))
        except JamJWSVerificationError:
            raise
        except Exception as e:
            logger.warning(
                f"ECDSA signature verification failed: {e}",
                exc_info=True,
            )
            raise JamJWSVerificationError(
                message=f"Invalid ECDSA signature: {e}"
            ) from e


class PSAlgorithm(BaseAlgorithm):
    """RSA PSS algorithms (PS256, PS384, PS512)."""

    def _get_private_key(self) -> Any:
        """Get private key for signing.

        Returns:
            Any: Private key object

        Raises:
            ValueError: If key cannot be loaded
        """
        key_bytes = (
            self._load_key_data(self._secret)
            if isinstance(self._secret, str | bytes)
            else None
        )
        return self._load_private_key(key_bytes, self._secret)

    def sign(self, data: bytes) -> str:
        """Sign data using RSA PSS.

        Args:
            data (bytes): Data to sign

        Returns:
            str: Base64url encoded signature
        """
        logger.debug("Signing with %s", self.alg)
        try:
            private_key = self._get_private_key()
            hash_alg = getattr(hashes, f"SHA{self.alg[2:]}")()
            sig = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hash_alg,
            )
            return __base64url_encode__(sig)
        except Exception as e:
            logger.error(
                f"Failed to sign with {self.alg}: {e}",
                exc_info=True,
            )
            raise JamJWSSigningError(message=f"Signing failed: {e}") from e

    def verify(self, sig: bytes, data: bytes, key: KeyLike) -> None:
        """Verify RSA PSS signature.

        Args:
            sig (bytes): Signature to verify
            data (bytes): Data that was signed
            key (KeyLike): Key for verification

        Raises:
            JamJWSVerificationError: If signature is invalid
        """
        logger.debug("Verifying %s signature", self.alg)
        try:
            pub_key = self._load_public_key_auto(key)
            hash_alg = getattr(hashes, f"SHA{self.alg[2:]}")()
            pub_key.verify(
                sig,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hash_alg,
            )
        except Exception as e:
            logger.warning(
                f"RSA PSS signature verification failed: {e}",
                exc_info=True,
            )
            raise JamJWSVerificationError(
                message=f"Invalid RSA PSS signature: {e}"
            ) from e


def create_algorithm(
    alg: str,
    secret: KeyLike,
    password: bytes | None,
) -> BaseAlgorithm:
    """Create algorithm instance based on algorithm name.

    Args:
        alg (str): Algorithm name
        secret (KeyLike): Secret key
        password (bytes | None): Password for private key

    Returns:
        BaseAlgorithm: Algorithm instance

    Raises:
        ValueError: If algorithm is not supported
    """
    if alg.startswith("HS"):
        return HSAlgorithm(alg, secret, password)
    if alg.startswith("RS"):
        return RSAlgorithm(alg, secret, password)
    if alg.startswith("ES"):
        return ESAlgorithm(alg, secret, password)
    if alg.startswith("PS"):
        return PSAlgorithm(alg, secret, password)

    raise JamAlgorithmError(message=f"Unsupported algorithm: {alg}")


SUPPORTED_ALGORITHMS = (
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
)


class BaseKeyAlgorithm(ABC):
    """Base class for JWE key management algorithms - RFC 7518 Section 4."""

    def __init__(
        self,
        alg: str,
        key: KeyLike,
        password: bytes | None,
    ) -> None:
        """Initialize key management algorithm.

        Args:
            alg: Algorithm name.
            key: Key for wrapping/unwrapping.
            password: Password for encrypted private keys.
        """
        self.alg = alg
        self._key = key
        self._password = password

    @abstractmethod
    def wrap_key(self, cek: bytes) -> tuple[bytes, dict[str, Any]]:
        """Wrap CEK (Content Encryption Key).

        Args:
            cek: Content Encryption Key to wrap.

        Returns:
            Tuple of (encrypted_key, header_updates).
        """
        raise NotImplementedError

    @abstractmethod
    def unwrap_key(self, encrypted_key: bytes, header: dict[str, Any]) -> bytes:
        """Unwrap CEK.

        Args:
            encrypted_key: Wrapped CEK.
            header: JWE header (may contain needed parameters).

        Returns:
            Unwrapped CEK.
        """
        raise NotImplementedError

    def _load_public_key(self) -> Any:
        """Load public key for encryption.

        Returns:
            Public key object.
        """
        if hasattr(self._key, "public_key"):
            return self._key.public_key()

        key_bytes = self._load_key_data(self._key)
        try:
            return serialization.load_pem_public_key(key_bytes)
        except ValueError:
            priv = serialization.load_pem_private_key(
                key_bytes, password=self._password
            )
            return priv.public_key()

    def _load_private_key(self) -> Any:
        """Load private key for decryption.

        Returns:
            Private key object.
        """
        if hasattr(self._key, "private_key"):
            return self._key.private_key()

        if isinstance(
            self._key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
        ):
            return self._key

        key_bytes = self._load_key_data(self._key)
        return serialization.load_pem_private_key(
            key_bytes, password=self._password
        )

    def _load_key_data(self, data: KeyLike) -> bytes:
        """Load key data from string or bytes."""
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            from pathlib import Path

            path = Path(data)
            try:
                is_file = path.is_file()
            except OSError:
                is_file = False
            return path.read_bytes() if is_file else data.encode()
        if isinstance(data, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
            data = data.public_key()
        return data.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


_RSA_OAEP_SHA256 = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=b"",
)


class RSAKeyAlgorithm(BaseKeyAlgorithm):
    """RSA Key Management algorithms - RFC 7518 Section 4.2."""

    _PADDING_MAP = {
        "RSA1_5": padding.PKCS1v15(),
        "RSA-OAEP": _RSA_OAEP_SHA256,
        "RSA-OAEP-256": _RSA_OAEP_SHA256,
    }

    def wrap_key(self, cek: bytes) -> tuple[bytes, dict[str, Any]]:
        """Wrap CEK using RSA."""
        logger.debug("Wrapping key with %s", self.alg)
        public_key = self._load_public_key()
        padding = self._PADDING_MAP.get(self.alg)
        if not padding:
            raise JamAlgorithmError(
                message=f"Unsupported RSA algorithm: {self.alg}"
            )

        encrypted_key = public_key.encrypt(cek, padding)
        return encrypted_key, {}

    def unwrap_key(self, encrypted_key: bytes, header: dict[str, Any]) -> bytes:
        """Unwrap CEK using RSA."""
        logger.debug("Unwrapping key with %s", self.alg)
        private_key = self._load_private_key()
        padding = self._PADDING_MAP.get(self.alg)
        if not padding:
            raise JamAlgorithmError(
                message=f"Unsupported RSA algorithm: {self.alg}"
            )

        return private_key.decrypt(encrypted_key, padding)


class AESKeyWrapAlgorithm(BaseKeyAlgorithm):
    """AES Key Wrap algorithms - RFC 7518 Section 4.4."""

    _KEY_SIZES = {"A128KW": 16, "A192KW": 24, "A256KW": 32}

    def wrap_key(self, cek: bytes) -> tuple[bytes, dict[str, Any]]:
        """Wrap CEK using AES Key Wrap."""
        logger.debug("Wrapping key with %s", self.alg)
        key_size = self._KEY_SIZES.get(self.alg, 16)

        if isinstance(self._key, str):
            key = self._key.encode()[:key_size]
        elif isinstance(self._key, bytes):
            key = self._key[:key_size]
        else:
            raise JamInvalidKeyTypeError(
                message=f"Invalid key type for {self.alg}"
            )

        encrypted_key = aes_key_wrap(key, cek)
        return encrypted_key, {}

    def unwrap_key(self, encrypted_key: bytes, header: dict[str, Any]) -> bytes:
        """Unwrap CEK using AES Key Wrap."""
        logger.debug("Unwrapping key with %s", self.alg)
        key_size = self._KEY_SIZES.get(self.alg, 16)

        if isinstance(self._key, str):
            key = self._key.encode()[:key_size]
        elif isinstance(self._key, bytes):
            key = self._key[:key_size]
        else:
            raise JamInvalidKeyTypeError(
                message=f"Invalid key type for {self.alg}"
            )

        return aes_key_unwrap(key, encrypted_key)


class ECDHKeyAlgorithm(BaseKeyAlgorithm):
    """ECDH-ES Key Management algorithms - RFC 7518 Section 4.6."""

    _CURVE_SIZES = {"P-256": 32, "P-384": 48, "P-521": 66}

    def wrap_key(self, cek: bytes) -> tuple[bytes, dict[str, Any]]:
        """Wrap CEK using ECDH."""
        logger.debug("Wrapping key with %s", self.alg)

        if self.alg in ("ECDH-ES", "ECDH-ES+A128KW"):
            curve = ec.SECP256R1()
        elif self.alg == "ECDH-ES+A192KW":
            curve = ec.SECP384R1()
        else:
            curve = ec.SECP521R1()

        ephemeral_key = ec.generate_private_key(curve)
        ephemeral_public_key = ephemeral_key.public_key()

        public_key = self._load_public_key()
        shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)

        alg_map = {
            "ECDH-ES+A128KW": 16,
            "ECDH-ES+A192KW": 24,
            "ECDH-ES+A256KW": 32,
        }
        key_length = alg_map.get(self.alg, (len(cek) + 7) // 8)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=b"",
            info=b"",
        ).derive(shared_key)

        if self.alg == "ECDH-ES":
            encrypted_key = derived_key[: len(cek)]
        else:
            key_wrap = AESKeyWrapAlgorithm(
                self.alg.replace("ECDH-ES+", ""),
                derived_key,
                None,
            )
            encrypted_key, _ = key_wrap.wrap_key(cek)

        crv_map = {
            "ECDH-ES": "P-256",
            "ECDH-ES+A128KW": "P-256",
            "ECDH-ES+A192KW": "P-384",
            "ECDH-ES+A256KW": "P-521",
        }
        crv = crv_map.get(self.alg, "P-256")

        curve_size = self._CURVE_SIZES.get(crv, 32)
        epk = {
            "kty": "EC",
            "crv": crv,
            "x": __base64url_encode__(
                ephemeral_public_key.public_numbers().x.to_bytes(
                    curve_size, "big"
                )
            ),
            "y": __base64url_encode__(
                ephemeral_public_key.public_numbers().y.to_bytes(
                    curve_size, "big"
                )
            ),
        }

        header: dict[str, Any] = {"epk": epk}
        if self.alg != "ECDH-ES":
            header["alg"] = self.alg

        return encrypted_key, header

    def unwrap_key(self, encrypted_key: bytes, header: dict[str, Any]) -> bytes:
        """Unwrap CEK using ECDH."""
        logger.debug("Unwrapping key with %s", self.alg)

        private_key = self._load_private_key()
        epk = header.get("epk", {})

        x = int.from_bytes(__base64url_decode__(epk["x"]), "big")
        y = int.from_bytes(__base64url_decode__(epk["y"]), "big")
        curve_name = epk.get("crv", "P-256")
        curve = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }[curve_name]

        ephemeral_public_key = ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=curve
        ).public_key()
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        alg_map = {
            "ECDH-ES+A128KW": 16,
            "ECDH-ES+A192KW": 24,
            "ECDH-ES+A256KW": 32,
        }
        key_length = alg_map.get(self.alg, len(encrypted_key))

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=b"",
            info=b"",
        ).derive(shared_key)

        if self.alg == "ECDH-ES":
            return derived_key[: len(encrypted_key)]
        else:
            key_wrap = AESKeyWrapAlgorithm(
                self.alg.replace("ECDH-ES+", ""),
                derived_key,
                None,
            )
            return key_wrap.unwrap_key(encrypted_key, header)


class AESGCMKeyAlgorithm(BaseKeyAlgorithm):
    """AES-GCM Key Wrap algorithms - RFC 7518 Section 4.7."""

    _KEY_SIZES = {"A128GCMKW": 16, "A256GCMKW": 32}

    def wrap_key(self, cek: bytes) -> tuple[bytes, dict[str, Any]]:
        """Wrap CEK using AES-GCM."""
        logger.debug("Wrapping key with %s", self.alg)
        key_size = self._KEY_SIZES.get(self.alg, 16)
        iv = os.urandom(12)

        if isinstance(self._key, str):
            key = self._key.encode()[:key_size]
        elif isinstance(self._key, bytes):
            key = self._key[:key_size]
        else:
            raise JamInvalidKeyTypeError(
                message=f"Invalid key type for {self.alg}"
            )

        aesgcm = AESGCM(key)
        encrypted_key = aesgcm.encrypt(iv, cek, None)

        return encrypted_key[:-16], {"iv": __base64url_encode__(iv)}

    def unwrap_key(self, encrypted_key: bytes, header: dict[str, Any]) -> bytes:
        """Unwrap CEK using AES-GCM."""
        logger.debug("Unwrapping key with %s", self.alg)
        key_size = self._KEY_SIZES.get(self.alg, 16)
        iv = __base64url_decode__(header.get("iv", ""))

        if isinstance(self._key, str):
            key = self._key.encode()[:key_size]
        elif isinstance(self._key, bytes):
            key = self._key[:key_size]
        else:
            raise JamInvalidKeyTypeError(
                message=f"Invalid key type for {self.alg}"
            )

        aesgcm = AESGCM(key)
        tag = encrypted_key[-16:]
        ciphertext = encrypted_key[:-16]

        return aesgcm.decrypt(iv, ciphertext + tag, None)


class PBES2KeyAlgorithm(BaseKeyAlgorithm):
    """PBES2 Key Management algorithms - RFC 7518 Section 4.8."""

    _ALG_MAP = {
        "PBES2-HS256+A128KW": (hashes.SHA256(), 16, "A128KW"),
        "PBES2-HS384+A192KW": (hashes.SHA384(), 24, "A192KW"),
        "PBES2-HS512+A256KW": (hashes.SHA512(), 32, "A256KW"),
    }

    def wrap_key(self, cek: bytes) -> tuple[bytes, dict[str, Any]]:
        """Wrap CEK using PBES2."""
        logger.debug("Wrapping key with %s", self.alg)

        hash_alg, key_size, kw_alg = self._ALG_MAP.get(
            self.alg, (hashes.SHA256(), 16, "A128KW")
        )

        password = self._password or b""
        if isinstance(password, str):
            password = password.encode()

        salt = os.urandom(16)
        iterations = 100000

        derived_key = PBKDF2HMAC(
            algorithm=hash_alg,
            length=key_size + 16,
            salt=salt,
            iterations=iterations,
        ).derive(password)

        kw_key = derived_key[key_size:]

        kw = AESKeyWrapAlgorithm(kw_alg, kw_key, None)
        encrypted_key, _ = kw.wrap_key(cek)

        return encrypted_key, {
            "p2s": __base64url_encode__(salt),
            "p2c": iterations,
        }

    def unwrap_key(self, encrypted_key: bytes, header: dict[str, Any]) -> bytes:
        """Unwrap CEK using PBES2."""
        logger.debug("Unwrapping key with %s", self.alg)

        hash_alg, key_size, kw_alg = self._ALG_MAP.get(
            self.alg, (hashes.SHA256(), 16, "A128KW")
        )

        password = self._password or b""
        if isinstance(password, str):
            password = password.encode()

        salt = __base64url_decode__(header.get("p2s", ""))
        iterations = header.get("p2c", 100000)

        derived_key = PBKDF2HMAC(
            algorithm=hash_alg,
            length=key_size + 16,
            salt=salt,
            iterations=iterations,
        ).derive(password)

        kw_key = derived_key[key_size:]

        kw = AESKeyWrapAlgorithm(kw_alg, kw_key, None)
        return kw.unwrap_key(encrypted_key, header)


class BaseEncAlgorithm(ABC):
    """Base class for JWE content encryption algorithms - RFC 7518 Section 5."""

    def __init__(self, enc: str) -> None:
        """Initialize content encryption algorithm.

        Args:
            enc: Algorithm name.
        """
        self.enc = enc

    @abstractmethod
    def get_key_length(self) -> int:
        """Return key length in bytes."""
        raise NotImplementedError

    @abstractmethod
    def get_iv_length(self) -> int:
        """Return IV length in bytes."""
        raise NotImplementedError

    @abstractmethod
    def encrypt(
        self, plaintext: bytes, iv: bytes, aad: bytes, key: bytes
    ) -> tuple[bytes, bytes]:
        """Encrypt plaintext.

        Args:
            plaintext: Data to encrypt.
            iv: Initialization vector.
            aad: Additional authenticated data.
            key: Encryption key.

        Returns:
            Tuple of (ciphertext, tag).
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(
        self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes, key: bytes
    ) -> bytes:
        """Decrypt ciphertext.

        Args:
            ciphertext: Encrypted data.
            iv: Initialization vector.
            tag: Authentication tag.
            aad: Additional authenticated data.
            key: Encryption key.

        Returns:
            Decrypted plaintext.
        """
        raise NotImplementedError


class AESGCMEncAlgorithm(BaseEncAlgorithm):
    """AES-GCM content encryption - RFC 7518 Section 5.1."""

    _KEY_SIZES = {"A128GCM": 16, "A256GCM": 32}
    _IV_LENGTH = 12

    def get_key_length(self) -> int:
        """Get the key length for the content encryption algorithm."""
        return self._KEY_SIZES.get(self.enc, 16)

    def get_iv_length(self) -> int:
        """Get the IV length for the content encryption algorithm."""
        return self._IV_LENGTH

    def encrypt(
        self, plaintext: bytes, iv: bytes, aad: bytes, key: bytes
    ) -> tuple[bytes, bytes]:
        """Encrypt using AES-GCM."""
        logger.debug("Encrypting with %s", self.enc)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, aad)
        return ciphertext[:-16], ciphertext[-16:]

    def decrypt(
        self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes, key: bytes
    ) -> bytes:
        """Decrypt using AES-GCM."""
        logger.debug("Decrypting with %s", self.enc)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, aad)


class AESCBCEncAlgorithm(BaseEncAlgorithm):
    """AES-CBC + HMAC content encryption - RFC 7518 Section 5.2."""

    _KEY_SIZES = {"A128CBC-HS256": 32, "A192CBC-HS384": 48, "A256CBC-HS512": 64}
    _IV_LENGTH = 16

    def get_key_length(self) -> int:
        """Get the key length for the content encryption algorithm."""
        return self._KEY_SIZES.get(self.enc, 32)

    def get_iv_length(self) -> int:
        """Get the IV length for the content encryption algorithm."""
        return self._IV_LENGTH

    def _get_hash(self):
        hash_map = {
            "A128CBC-HS256": "sha256",
            "A192CBC-HS384": "sha384",
            "A256CBC-HS512": "sha512",
        }
        return hash_map.get(self.enc, "sha256")

    def encrypt(
        self, plaintext: bytes, iv: bytes, aad: bytes, key: bytes
    ) -> tuple[bytes, bytes]:
        """Encrypt using AES-CBC + HMAC."""
        logger.debug("Encrypting with %s", self.enc)

        mac_key_len = self.get_key_length() // 2

        mac_key = key[:mac_key_len]
        enc_key = key[mac_key_len:]

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padded = self._pkcs7_pad(plaintext, 16)
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        hash_name = self._get_hash()
        aad_len = (len(aad) * 8).to_bytes(8, "big")
        iv_len = (len(iv) * 8).to_bytes(8, "big")
        ct_len = (len(ciphertext) * 8).to_bytes(8, "big")

        mac_input = aad + iv + ciphertext + aad_len + iv_len + ct_len
        tag = hmac.new(mac_key, mac_input, hash_name).digest()

        return ciphertext, tag[:mac_key_len]

    def decrypt(
        self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes, key: bytes
    ) -> bytes:
        """Decrypt using AES-CBC + HMAC."""
        logger.debug("Decrypting with %s", self.enc)

        mac_key_len = self.get_key_length() // 2
        enc_key_len = self.get_key_length() // 2  # noqa

        mac_key = key[:mac_key_len]
        enc_key = key[mac_key_len:]

        hash_name = self._get_hash()
        aad_len = (len(aad) * 8).to_bytes(8, "big")
        iv_len = (len(iv) * 8).to_bytes(8, "big")
        ct_len = (len(ciphertext) * 8).to_bytes(8, "big")

        mac_input = aad + iv + ciphertext + aad_len + iv_len + ct_len
        expected_tag = hmac.new(mac_key, mac_input, hash_name).digest()[
            :mac_key_len
        ]

        if not hmac.compare_digest(tag, expected_tag):
            raise JamJWSValidationError(message="HMAC verification failed")

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        return self._pkcs7_unpad(padded)

    def _pkcs7_pad(self, data: bytes, block_size: int) -> bytes:
        """Apply PKCS#7 padding."""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding.

        Args:
            data: Padded data.

        Returns:
            Unpadded data.

        Raises:
            ValueError: If padding is invalid.
        """
        if not data:
            raise JamInvalidPaddingError(message="Empty data for unpadding")
        padding_length = data[-1]
        if not (1 <= padding_length <= 16):
            raise JamInvalidPaddingError(message="Invalid padding length")
        if padding_length > len(data):
            raise JamInvalidPaddingError(
                message="Invalid padding: exceeds data length"
            )
        if any(b != padding_length for b in data[-padding_length:]):
            raise JamInvalidPaddingError(message="Invalid PKCS#7 padding")
        return data[:-padding_length]


def create_key_algorithm(
    alg: str,
    key: KeyLike,
    password: bytes | None,
) -> BaseKeyAlgorithm:
    """Create JWE key management algorithm instance.

    Args:
        alg: Algorithm name.
        key: Key for wrapping/unwrapping.
        password: Password for encrypted private keys.

    Returns:
        BaseKeyAlgorithm instance.

    Raises:
        ValueError: If algorithm is not supported.
    """
    if alg in ("RSA1_5", "RSA-OAEP", "RSA-OAEP-256"):
        return RSAKeyAlgorithm(alg, key, password)
    if alg in ("A128KW", "A192KW", "A256KW"):
        return AESKeyWrapAlgorithm(alg, key, password)
    if alg in ("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"):
        return ECDHKeyAlgorithm(alg, key, password)
    if alg in ("A128GCMKW", "A256GCMKW"):
        return AESGCMKeyAlgorithm(alg, key, password)
    if alg.startswith("PBES2"):
        return PBES2KeyAlgorithm(alg, key, password)

    raise JamAlgorithmError(message=f"Unsupported key algorithm: {alg}")


def create_enc_algorithm(
    enc: str,
) -> BaseEncAlgorithm:
    """Create JWE content encryption algorithm instance.

    Args:
        enc: Algorithm name.

    Returns:
        BaseEncAlgorithm instance.

    Raises:
        ValueError: If algorithm is not supported.
    """
    if enc in ("A128GCM", "A256GCM"):
        return AESGCMEncAlgorithm(enc)
    if enc in ("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"):
        return AESCBCEncAlgorithm(enc)

    raise JamAlgorithmError(
        message=f"Unsupported content encryption algorithm: {enc}"
    )


SUPPORTED_KEY_ALGORITHMS = frozenset(
    {
        "RSA1_5",
        "RSA-OAEP",
        "RSA-OAEP-256",
        "A128KW",
        "A192KW",
        "A256KW",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
        "A128GCMKW",
        "A256GCMKW",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    }
)

SUPPORTED_ENC_ALGORITHMS = frozenset(
    {
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A256GCM",
    }
)

REGISTERED_HEADER_NAMES = frozenset(
    {
        "alg",
        "jku",
        "jwk",
        "kid",
        "x5u",
        "x5c",
        "x5t",
        "x5t#S256",
        "typ",
        "cty",
        "crit",
    }
)

REGISTERED_JWK_PARAMS = frozenset(
    {"kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256"}
)

RESERVED_CLAIMS = frozenset({"typ", "cty"})
