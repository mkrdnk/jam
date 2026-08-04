# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
import hashlib
import hmac
import logging
import secrets
from typing import Any, Literal, TypeVar, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from jam.__base_encoder__ import BaseEncoder
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamConfigurationError,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamPASETOInvalidPurpose,
    JamPASETOInvalidTokenFormat,
    JamPASETOKeyVerificationError,
)
from jam.lists import BaseList, build_list
from jam.paseto.utils import (
    __gen_hash__,
    __pae__,
    base64url_decode,
    base64url_encode,
)
from jam.utils.config_meta import ConfigMeta
from jam.utils.xchacha20poly1305 import (
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)


logger = logging.getLogger(__name__)


PASETO = TypeVar("PASETO", bound="BasePASETO")


class LegacyAEADMixin:
    """Shared local encryption for PASETO v1/v3 (AES-256-CTR + HMAC-SHA384)."""

    _secret: Any
    _encrypt: Any
    _decrypt: Any
    _decode_footer: Any

    def _encode_local(
        self,
        header: str,
        payload: bytes,
        footer: bytes,
    ) -> bytes:
        """Encode a 'local' token.

        Args:
            header (str): Version header (e.g. "v1.local.").
            payload (bytes): Serialized payload.
            footer (bytes): Serialized footer.

        Returns:
            bytes: Encoded token.
        """
        header_b = header.encode("ascii")
        nonce = secrets.token_bytes(32)
        pl = __gen_hash__(nonce, payload, 32)

        hkdf_params = {
            "algorithm": hashes.SHA384(),
            "length": 32,
            "salt": pl[0:16],
        }
        ek = HKDF(info=b"paseto-encryption-key", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )
        ak = HKDF(info=b"paseto-auth-key-for-aead", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )

        ciphertext = self._encrypt(ek, pl[16:], payload)
        pre_auth = __pae__([header_b, pl, ciphertext, footer])
        tag = hmac.new(ak, pre_auth, hashlib.sha384).digest()

        token = header_b + base64url_encode(pl + ciphertext + tag)
        if footer:
            token += b"." + base64url_encode(footer)
        return token

    def _decode_local(
        self, token: str, serializer: type[BaseEncoder] | BaseEncoder
    ) -> tuple[Any, Any]:
        """Decode a 'local' token.

        Args:
            token (str): PASETO token.
            serializer (type[BaseEncoder] | BaseEncoder): JSON serializer.

        Returns:
            tuple[Any, Any]: Payload and footer.

        Raises:
            JamPASETOInvalidTokenFormat: If the token format or tag is invalid.
            JamPASETOKeyVerificationError: If the token cannot be decrypted.
        """
        parts = token.encode("utf-8").split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat
        header = b".".join(parts[:2]) + b"."
        if header != f"{self._VERSION}.local.".encode("ascii"):
            raise JamPASETOInvalidTokenFormat(
                message="Invalid PASETO header",
                error_code="paseto.validation.invalid_header",
            )

        payload_part = parts[2]
        footer_part = parts[3] if len(parts) > 3 else b""

        decoded = base64url_decode(payload_part)
        if len(decoded) < 80:
            raise JamPASETOInvalidTokenFormat(
                message="Invalid payload size.",
                error_code="paseto.validation.invalid_payload_size",
            )

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
        ek = HKDF(info=b"paseto-encryption-key", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )
        ak = HKDF(info=b"paseto-auth-key-for-aead", **hkdf_params).derive(  # type: ignore[arg-type]
            self._secret
        )

        pre_auth = __pae__([header, pl, ciphertext, footer_decoded])
        expected_tag = hmac.new(ak, pre_auth, hashlib.sha384).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise JamPASETOInvalidTokenFormat(
                message="Invalid authentication tag",
                error_code="paseto.validation.invalid_authentication_tag",
            )

        payload = serializer.loads(self._decrypt(ek, pl[16:], ciphertext))
        return payload, self._decode_footer(footer_decoded, serializer)


class XChaChaMixin:
    """Shared local encryption for PASETO v2/v4 (XChaCha20-Poly1305)."""

    _secret: Any
    _decode_footer: Any

    def _encode_local(
        self,
        header: str,
        payload: bytes,
        footer: bytes,
    ) -> bytes:
        """Encode a 'local' token.

        Args:
            header (str): Version header (e.g. "v2.local.").
            payload (bytes): Serialized payload.
            footer (bytes): Serialized footer.

        Returns:
            bytes: Encoded token.
        """
        bheader = header.encode("ascii")
        bfooter = footer or b""
        nonce = secrets.token_bytes(24)
        aad = __pae__([bheader, bfooter])

        ciphertext = xchacha20poly1305_encrypt(
            self._secret, nonce, payload, aad
        )

        token = bheader + base64url_encode(nonce + ciphertext)
        if bfooter:
            token += b"." + base64url_encode(bfooter)
        return token

    def _decode_local(
        self, token: str, serializer: type[BaseEncoder] | BaseEncoder
    ) -> tuple[Any, Any]:
        """Decode a 'local' token.

        Args:
            token (str): PASETO token.
            serializer (type[BaseEncoder] | BaseEncoder): JSON serializer.

        Returns:
            tuple[Any, Any]: Payload and footer.

        Raises:
            JamPASETOInvalidTokenFormat: If the token format is invalid.
            JamPASETOKeyVerificationError: If the token cannot be decrypted.
        """
        parts = token.encode().split(b".")
        if len(parts) < 3:
            raise JamPASETOInvalidTokenFormat
        header = b".".join(parts[:2]) + b"."
        if header != f"{self._VERSION}.local.".encode("ascii"):
            raise JamPASETOInvalidTokenFormat(
                message="Invalid PASETO header",
                error_code="paseto.validation.invalid_header",
            )

        body = base64url_decode(parts[2])
        if len(body) < 24 + 16:
            raise JamPASETOInvalidTokenFormat(message="Invalid token body")
        footer = base64url_decode(parts[3]) if len(parts) > 3 else b""

        nonce = body[:24]
        ciphertext = body[24:]
        aad = __pae__([header, footer])

        try:
            plaintext = xchacha20poly1305_decrypt(
                self._secret, nonce, ciphertext, aad
            )
        except Exception:
            raise JamPASETOKeyVerificationError(
                message="Invalid authentication or corrupt ciphertext"
            )

        payload = serializer.loads(plaintext)
        return payload, self._decode_footer(footer, serializer)


class KeyLoadMixin:
    """Shared PEM/DER key loading ladder for asymmetric PASETO versions."""

    @staticmethod
    def _load_key(
        key_bytes: bytes,
        private_types: tuple[type, ...],
        public_types: tuple[type, ...],
        curve: str | None = None,
    ) -> tuple[Any | None, Any | None]:
        """Load a private or public key from PEM/DER bytes.

        Args:
            key_bytes (bytes): Key bytes.
            private_types (tuple[type, ...]): Accepted private key types.
            public_types (tuple[type, ...]): Accepted public key types.
            curve (str | None): Optional curve name filter.

        Returns:
            tuple[Any | None, Any | None]: (private, public) key or None.
        """
        for loader in (
            serialization.load_pem_private_key,
            serialization.load_der_private_key,
        ):
            try:
                key = loader(key_bytes, password=None)
            except Exception:
                continue
            if isinstance(key, private_types) and (
                curve is None or key.curve.name == curve
            ):
                return key, None

        for loader in (
            serialization.load_pem_public_key,
            serialization.load_der_public_key,
        ):
            try:
                key = loader(key_bytes)
            except Exception:
                continue
            if isinstance(key, public_types) and (
                curve is None or key.curve.name == curve
            ):
                return None, key

        return None, None


class BasePASETO(ABC, metaclass=ConfigMeta):
    """Base PASETO instance."""

    _VERSION: str
    _CONFIG_POINTER: str = "jam.paseto"

    def __init__(
        self,
        purpose: Literal["local", "public"],
        secret_key: str | bytes | Any,
        list: dict[str, Any] | BaseList | None = None,
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
        self.list: BaseList | None = build_list(list) if list else None
        self._set_key(secret_key)

    def _set_key(self, secret_key: str | bytes | Any) -> None:
        """Process the key for the given purpose.

        Args:
            secret_key (str | bytes | Any): Secret or asymmetric key.

        Raises:
            NotImplementedError: If not implemented by the version class.
        """
        raise NotImplementedError

    @abstractmethod
    def _encode_local(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        """Encode a 'local' token."""
        raise NotImplementedError

    @abstractmethod
    def _encode_public(
        self, header: str, payload: bytes, footer: bytes
    ) -> bytes:
        """Encode a 'public' token."""
        raise NotImplementedError

    @abstractmethod
    def _decode_local(
        self, token: str, serializer: type[BaseEncoder] | BaseEncoder
    ) -> tuple[Any, Any]:
        """Decode a 'local' token."""
        raise NotImplementedError

    @abstractmethod
    def _decode_public(
        self, token: str, serializer: type[BaseEncoder] | BaseEncoder
    ) -> tuple[Any, Any]:
        """Decode a 'public' token."""
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

    @property
    def purpose(self) -> Literal["local", "public"] | None:
        """Return PASETO purpose."""
        return self._purpose

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

    def _normalize_footer(
        self, footer: Any, serializer: type[BaseEncoder] | BaseEncoder
    ) -> bytes:
        """Normalize a footer into bytes.

        Args:
            footer (Any): dict, list, str, bytes or None.
            serializer (type[BaseEncoder] | BaseEncoder): JSON serializer.

        Returns:
            bytes: Footer bytes.
        """
        if isinstance(footer, dict | list):
            return serializer.dumps(cast(dict[str, Any], footer))
        if isinstance(footer, str):
            return footer.encode("utf-8")
        if isinstance(footer, bytes | bytearray):
            return bytes(footer)
        return b""

    def _decode_footer(
        self,
        footer_decoded: bytes,
        serializer: type[BaseEncoder] | BaseEncoder,
    ) -> Any:
        """Decode a footer, falling back to str/bytes.

        Args:
            footer_decoded (bytes): Raw footer bytes.
            serializer (type[BaseEncoder] | BaseEncoder): JSON serializer.

        Returns:
            Any: dict, str, bytes or None.
        """
        if not footer_decoded:
            return None
        try:
            return serializer.loads(footer_decoded)
        except Exception:
            try:
                return footer_decoded.decode("utf-8")
            except Exception:
                return footer_decoded

    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | bytes | None = None,
        serializer: type[BaseEncoder] | BaseEncoder = JsonEncoder,
    ) -> str:
        """Encode a PASETO token.

        Args:
            payload (dict[str, Any]): Payload for token.
            footer (dict[str, Any] | str | bytes | None): Token footer.
            serializer (type[BaseEncoder] | BaseEncoder): JSON serializer.

        Returns:
            str: Encoded token.

        Raises:
            JamPASETOInvalidPurpose: If the purpose is not "local" or "public".
        """
        header = f"{self._VERSION}.{self._purpose}."
        payload_bytes = serializer.dumps(payload)
        footer_bytes = self._normalize_footer(footer, serializer)

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
    ) -> tuple[dict[str, Any], Any]:
        """Decode a PASETO token.

        Args:
            token (str): Token.
            serializer (type[BaseEncoder] | BaseEncoder): JSON serializer.

        Returns:
            tuple[dict[str, Any], Any]: Payload and footer.

        Raises:
            JamPASETOInvalidPurpose: If the purpose is not "local" or "public".
        """
        self._list_check(token)
        if token.startswith(f"{self._VERSION}.local."):
            return self._decode_local(token, serializer)
        if token.startswith(f"{self._VERSION}.public."):
            return self._decode_public(token, serializer)
        raise JamPASETOInvalidPurpose
