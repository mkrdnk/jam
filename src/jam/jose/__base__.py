# -*- coding: utf-8 -*-

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from jam.lists import BaseJWTList


class BaseJWT(ABC):
    """Base JWT."""

    JWS: type[BaseJWS]
    list: BaseJWTList | None = None

    @property
    @abstractmethod
    def jti(self) -> str:
        """The JWT ID."""
        raise NotImplementedError

    @abstractmethod
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
        """Encode the JWT with the given expire, header, and payload.

        Args:
            exp (int | None): The expiration time in seconds.
            nbf (int | None): The not-before time in seconds.
            iss (str | None): The issuer.
            sub (str | None): The subject.
            aud (str | None): The audience.
            jti (str | None): The JWT ID.
            header (dict[str, Any] | None): The header to include in the JWT.
            payload (dict[str, Any] | None): The payload to include in the JWT.

        Returns:
            str: The encoded JWT.
        """
        raise NotImplementedError

    @abstractmethod
    def decode(
        self,
        token: str,
        validate_claims: bool = True,
    ) -> dict[str, Any]:
        """Decode the JWT and return the header and payload.

        Args:
            token (str): JWT
            validate_claims (bool): Whether to validate exp/nbf claims.

        Returns:
            dict with 'header' and 'payload' keys (both dicts).

        Raises:
            JamJWTExpired: If token is expired.
            JamJWTNotYetValid: If token is not yet valid.
        """
        raise NotImplementedError

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes | str | dict[str, Any],
        header: dict[str, Any] | None = None,
    ) -> str:
        """Encrypt plaintext.

        Produces JWE Compact Serialization:
        BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)

        Args:
            plaintext: Data to encrypt. If str, will be encoded to UTF-8.
                If dict, will be JSON encoded.
            header: JWE header (must include 'alg' and 'enc').

        Returns:
            JWE compact serialization string.

        Raises:
            JamJWEEncryptionError: If encryption fails.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, token: str) -> dict[str, Any] | bytes:
        """Decrypt JWE token.

        Args:
            token: JWE compact serialization string.

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            JamJWEDecryptionError: If decryption fails.
        """
        raise NotImplementedError


class BaseJWS(ABC):
    """Base JSON Web Signature - RFC 7515."""

    @abstractmethod
    def serialize_compact(
        self,
        protected: dict[str, Any],
        payload: bytes | str,
    ) -> str:
        """Create JWS Compact Serialization.

        Args:
            protected (dict[str, Any]): Protected header.
            payload (bytes | str): Payload to sign.

        Returns:
            str: JWS in compact serialization format:
                 BASE64URL(protected).BASE64URL(payload).BASE64URL(signature)
        """
        raise NotImplementedError

    @abstractmethod
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
            JamJWSVerificationError: If validation fails.
        """
        raise NotImplementedError

    @abstractmethod
    def sign(
        self,
        header: dict[str, Any],
        data: bytes | str | dict[str, Any],
    ) -> str:
        """Sign data and return JWS compact serialization.

        Args:
            header: JWS header (must include 'alg').
            data: Data to sign. If dict, will be JSON encoded.

        Returns:
            str: JWS compact serialization string.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(
        self,
        token: str,
        validate: bool = True,
    ) -> dict[str, Any]:
        """Verify JWS token and return header/payload.

        Args:
            token: JWS compact serialization token.
            validate: Whether to validate signature. Defaults to True.

        Returns:
            dict[str, Any]: Parsed JWS with 'header' and 'payload' keys.

        Raises:
            JamJWSVerificationError: If validation fails.
        """
        raise NotImplementedError


class BaseJWK(ABC):
    """JSON Web Key - RFC 7517."""

    @property
    @abstractmethod
    def kty(self) -> str:
        """Key type (kty) - RSA, EC, oct, etc."""
        raise NotImplementedError

    @property
    @abstractmethod
    def alg(self) -> str | None:
        """Algorithm (alg) - RS256, ES256, etc."""
        raise NotImplementedError

    @property
    @abstractmethod
    def kid(self) -> str | None:
        """Key ID (kid)."""
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def validate(data: dict[str, Any]) -> BaseJWK:
        """Validate and create JWK from dict.

        Args:
            data: JWK dict to validate.

        Returns:
            JWK instance.

        Raises:
            ValueError: If JWK is invalid.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> BaseJWK:
        """Create JWK from dict.

        Args:
            data: JWK dict.

        Returns:
            JWK instance.
        """
        raise NotImplementedError

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Convert JWK to dict.

        Returns:
            JWK dict.
        """
        raise NotImplementedError

    @abstractmethod
    def sign(self, data: bytes, alg: str | None = None) -> str:
        """Sign data using JWK.

        Args:
            data: Data to sign.
            alg: Algorithm to use. If None, uses default for kty.

        Returns:
            JWS compact serialization string.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, token: str, alg: str | None = None) -> dict[str, Any]:
        """Verify JWS token and return payload.

        Args:
            token: JWS compact serialization token.
            alg: Algorithm to use. If None, uses default for kty.

        Returns:
            dict with 'header' and 'payload' keys.
        """
        raise NotImplementedError


class BaseJWKSet(ABC):
    """JWK Set - RFC 7517 Section 5."""

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> BaseJWKSet:
        """Create JWKSet from dict.

        Args:
            data: JWKSet dict with 'keys' array.

        Returns:
            JWKSet instance.
        """
        raise NotImplementedError

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Convert JWKSet to dict.

        Returns:
            dict[str, Any]: JWKSet dict with 'keys' array.
        """
        raise NotImplementedError

    @abstractmethod
    def get_by_kid(self, kid: str) -> dict[str, Any] | None:
        """Get JWK by key ID (kid).

        Args:
            kid (str): Key ID to search for.

        Returns:
            dict[str, Any] | None: JWK dict if found, None otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def get_by_kty(self, kty: str) -> list[dict[str, Any]]:
        """Get all JWKs by key type.

        Args:
            kty (str): Key type (RSA, EC, oct).

        Returns:
            list[dict[str, Any]]: List of matching JWK dicts.
        """
        raise NotImplementedError

    @abstractmethod
    def filter(self, **criteria: Any) -> list[dict[str, Any]]:
        """Filter JWKs by criteria.

        Args:
            **criteria: Filter criteria (kty, use, alg, key_ops, kid).

        Returns:
            list[dict[str, Any]]: List of matching JWK dicts.
        """
        raise NotImplementedError


class BaseJWKStorage(ABC):
    """Base JWK Storage."""

    @abstractmethod
    def get(self, name: str) -> dict[str, Any] | None:
        """Get a key by name.

        Args:
            name (str): The name of the key to retrieve.

        Returns:
            dict[str, Any] | None: JWK dict if found.
        """
        raise NotImplementedError

    @abstractmethod
    def store(self, name: str, jwk: dict[str, Any]) -> None:
        """Store a JWK with the given name.

        Args:
            name (str): The name of the key to store.
            jwk (dict[str, Any]): JWK dict to store.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(self, name: str) -> None:
        """Delete a key by name.

        Args:
            name (str): The name of the key to delete.
        """
        raise NotImplementedError


class BaseJWE(ABC):
    """Base JSON Web Encryption - RFC 7516."""

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes | str | dict[str, Any],
        header: dict[str, Any] | None = None,
    ) -> str:
        """Encrypt plaintext.

        Produces JWE Compact Serialization:
        BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)

        Args:
            plaintext: Data to encrypt. If str, will be encoded to UTF-8.
                If dict, will be JSON encoded.
            header: JWE header (must include 'alg' and 'enc').

        Returns:
            JWE compact serialization string.

        Raises:
            JamJWEEncryptionError: If encryption fails.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, token: str) -> bytes:
        """Decrypt JWE token.

        Args:
            token: JWE compact serialization string.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            JamJWEDecryptionError: If decryption fails.
        """
        raise NotImplementedError
