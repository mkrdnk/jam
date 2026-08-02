# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any, Literal, TypeVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamConfigurationError,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamPASETOInvalidPurpose,
    JamPASETOInvalidRSAKey,
)
from jam.lists import BaseList
from jam.logger import BaseLogger, logger
from jam.utils.config_meta import ConfigMeta


PASETO = TypeVar("PASETO", bound="BasePASETO")
RSAKeyLike = str | bytes | rsa.RSAPrivateKey | rsa.RSAPublicKey


class BasePASETO(ABC, metaclass=ConfigMeta):
    """Base PASETO instance."""

    _VERSION: str
    _CONFIG_POINTER: str = "jam.paseto"

    def __init__(
        self,
        purpose: Literal["local", "public"],
        secret_key: str | bytes | Any,
        list: dict[str, Any] | BaseList | None = None,
        logger: BaseLogger = logger,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize PASETO instance.

        Args:
            purpose (Literal["local", "public"]): 'local' (symmetric encryption)
                or 'public' (asymmetric signing).
            secret_key (str | bytes | Any): Raw bytes or PEM text depending on
                purpose. Can be a path to a key file.
            list (dict[str, Any] | BaseList | None): List config or list
                instance for token storage.
            logger (BaseLogger): Logger instance.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.paseto".

        Raises:
            JamPASETOInvalidPurpose: If purpose is not "local" or "public".
        """
        if purpose not in ("local", "public"):
            raise JamPASETOInvalidPurpose(details={"purpose": purpose})

        self._secret: Any | None = None
        self._public_key: (
            rsa.RSAPublicKey
            | ed25519.Ed25519PublicKey
            | ec.EllipticCurvePublicKey
            | None
        ) = None
        self._purpose: Literal["local", "public"] = purpose
        self._logger = logger
        self.list: BaseList | None = self._list_built(list) if list else None
        self._set_key(secret_key)

    def _set_key(self, secret_key: str | bytes | Any) -> None:
        """Process the key for the given purpose.

        Args:
            secret_key (str | bytes | Any): Secret or asymmetric key.

        Raises:
            NotImplementedError: If not implemented by the version class.
        """
        raise NotImplementedError

    @classmethod
    def key(
        cls: type[PASETO],
        purpose: Literal["local", "public"],
        secret_key: str | bytes | Any,
        **kwargs: Any,
    ) -> PASETO:
        """Create a PASETO instance (alias for ``cls(purpose, secret_key)``).

        Args:
            purpose (Literal["local", "public"]): PASETO purpose.
            secret_key (str | bytes | Any): Secret or asymmetric key.
            **kwargs: Additional arguments passed to the constructor.

        Returns:
            PASETO: Configured PASETO instance.
        """
        return cls(purpose=purpose, secret_key=secret_key, **kwargs)

    def _list_add(self, token: str) -> None:
        """Add a token to the white list if configured.

        Args:
            token (str): PASETO token.
        """
        if self.list and self.list.__list_type__ == "white":
            self.list.add(token)

    def _list_check(self, token: str) -> None:
        """Check the token in the white/black list if configured.

        Args:
            token (str): PASETO token.

        Raises:
            JamJWTNotInWhiteList: If token is not in the white list.
            JamJWTInBlackList: If token is in the black list.
        """
        if not self.list:
            return
        match self.list.__list_type__:
            case "white":
                if not self.list.check(token):
                    raise JamJWTNotInWhiteList
            case "black":
                if self.list.check(token):
                    raise JamJWTInBlackList
            case _:
                raise JamConfigurationError(
                    message="Invalid PASETO list type",
                    error_code="configuration.paseto.unknown_list_type",
                )

    def _list_built(self, list_config: dict[str, Any] | BaseList) -> BaseList:
        """Build a list instance from config or return it as-is.

        Args:
            list_config (dict[str, Any] | BaseList): List config or list instance.

        Returns:
            BaseList: Built list instance.
        """
        if isinstance(list_config, BaseList):
            return list_config
        match list_config["backend"]:
            case "redis":
                from jam.lists.redis import RedisList

                return RedisList(
                    type=list_config.get("type", "black"),
                    prefix=list_config.get("prefix", "jwt_list"),
                    redis_uri=list_config.get("redis_uri"),
                    ttl=list_config.get("ttl"),
                    logger=self._logger,
                )
            case "json":
                from jam.lists.json import JSONList

                return JSONList(
                    type=list_config.get("type", "black"),
                    prefix=list_config.get("prefix", "jwt_list"),
                    json_path=list_config.get("json_path", "whitelist.json"),
                    logger=self._logger,
                )
            case "memory":
                from jam.lists.memory import MemoryList

                return MemoryList(
                    type=list_config.get("type", "black"),
                    prefix=list_config.get("prefix", "jwt_list"),
                    logger=self._logger,
                )
            case _:
                raise JamConfigurationError(
                    message=f"Unknown list backend: {list_config['backend']}"
                )

    @property
    def purpose(self) -> Literal["local", "public"] | None:
        """Return PASETO purpose."""
        return self._purpose

    @staticmethod
    def load_rsa_key(key: RSAKeyLike | None, *, private: bool = True) -> Any:
        """Load rsa key from string | bytes.

        Args:
            key (RSAKeyLike | None): RSA Key
            private (bool): Private or public

        Raises:
            JamPASETOInvalidRSAKey: Invalid RSA key format.
        """
        if key is None:
            return None
        if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
            return key
        if isinstance(key, str):
            key_bytes: bytes = key.encode("utf-8")
        else:
            key_bytes = key
        try:
            if private:
                return serialization.load_pem_private_key(
                    key_bytes, password=None
                )  # type: ignore[no-any-return]
            else:
                return serialization.load_pem_public_key(key_bytes)  # type: ignore[no-any-return]
        except ValueError:
            try:
                if private:
                    return serialization.load_der_private_key(
                        key_bytes,
                        password=None,  # type: ignore[arg-type]
                    )
                else:
                    return serialization.load_der_public_key(key_bytes)  # type: ignore[arg-type]
            except Exception as e:
                raise JamPASETOInvalidRSAKey(
                    message=f"Invalid RSA {'private' if private else 'public'} key format.",
                    details={"error": str(e)},
                )

    @staticmethod
    def _rsa_pem_check(key: RSAKeyLike) -> bool:
        if isinstance(key, str):
            if key.startswith("-----BEGIN PRIVATE"):
                return True
            elif key.startswith("-----BEGIN RSA PRIVATE"):
                return True
            elif key.startswith("-----BEGIN EC PRIVATE"):
                return True
        elif isinstance(key, bytes):
            if key.startswith(b"-----BEGIN PRIVATE"):
                return True
            elif key.startswith(b"-----BEGIN RSA PRIVATE"):
                return True
            elif key.startswith(b"-----BEGIN EC PRIVATE"):
                return True
        elif isinstance(key, rsa.RSAPrivateKey):
            return True
        return False

    @staticmethod
    def _encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
        """Encrypt data using AES-256-CTR."""
        try:
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext
        except Exception as e:
            raise ValueError(f"Failed to encrypt: {e}")

    @staticmethod
    def _decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
        """Decrypt data using AES-256-CTR."""
        try:
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(data) + decryptor.finalize()
            return plaintext
        except Exception as e:
            raise ValueError(f"Failed to decrypt: {e}")

    @abstractmethod
    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> str:
        """Generate token from key instance.

        Args:
            payload (dict[str, Any]): Payload for token
            footer (dict[str, Any] | str  | None): Token footer
            serializer (BaseEncoder): JSON Encoder
        """
        raise NotImplementedError

    @abstractmethod
    def decode(
        self,
        token: str,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Decode PASETO.

        Args:
            token (str): Token
            serializer (BaseEncoder): JSON Encoder

        Returns:
            tuple[dict[str, Any], Optional[dict[str, Any]]]: Payload, footer
        """
        raise NotImplementedError
