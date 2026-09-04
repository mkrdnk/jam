# -*- coding: utf-8 -*-

"""Common KeyChain contract and lifecycle rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import secrets

from jam.exceptions import JamKeyChainError
from jam.utils import (
    generate_ecdsa_p384_keypair,
    generate_ed25519_keypair,
    generate_rsa_key_pair,
)


class KeyStatus(str, Enum):
    """States a key can have during its lifecycle."""

    STANDBY = "standby"
    CURRENT = "current"
    RETIRED = "retired"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """Non-secret key metadata returned by KeyChain administration APIs."""

    id: str
    status: KeyStatus
    created_at: datetime
    algorithm: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class _StoredKey:
    """Private storage representation, including secret material."""

    info: KeyInfo
    material: bytes


class BaseKeyChain(ABC):
    """Manage keys used to issue and verify one kind of credential."""

    def __init__(self, algorithm: str, purpose: str | None = None) -> None:
        """Initialize a chain for a signing algorithm or PASETO purpose."""
        self.algorithm = algorithm.upper()
        self.purpose = purpose

    @abstractmethod
    def _load(self, key_id: str) -> _StoredKey | None:
        """Load a stored key, including material."""

    @abstractmethod
    def _save(self, key: _StoredKey) -> None:
        """Persist a stored key without replacing an existing key."""

    @abstractmethod
    def _replace(self, key: _StoredKey) -> None:
        """Atomically replace metadata/material for an existing key."""

    @abstractmethod
    def _delete(self, key_id: str) -> None:
        """Physically delete a non-current stored key."""

    @abstractmethod
    def _all(self) -> list[_StoredKey]:
        """Return every stored key."""

    def list(self, include_revoked: bool = True) -> list[KeyInfo]:
        """List key metadata without revealing secret material."""
        keys = self._all()
        if not include_revoked:
            keys = [key for key in keys if key.info.status != KeyStatus.REVOKED]
        return sorted((key.info for key in keys), key=lambda info: info.created_at)

    def get(self, key_id: str) -> KeyInfo:
        """Return non-secret metadata for one key."""
        return self._require(key_id).info

    def current(self) -> KeyInfo | None:
        """Return the current issuing key, if one is configured."""
        current = [
            key.info for key in self._all() if key.info.status == KeyStatus.CURRENT
        ]
        if len(current) > 1:
            raise JamKeyChainError(
                "KeyChain has more than one current key.",
                error_code="keychain.invalid_current",
            )
        return current[0] if current else None

    def add(self, key_id: str, material: bytes | str | None = None) -> KeyInfo:
        """Add a generated or supplied standby key."""
        self._validate_id(key_id)
        if self._load(key_id) is not None:
            raise JamKeyChainError(
                f"Key '{key_id}' already exists.",
                error_code="keychain.duplicate_key",
            )
        if material is None:
            material = self._generate_material()
        if isinstance(material, str):
            material = material.encode()
        info = KeyInfo(
            id=key_id,
            status=KeyStatus.STANDBY,
            created_at=datetime.now(timezone.utc),
            algorithm=self.algorithm,
            fingerprint=self._fingerprint(material),
        )
        self._save(_StoredKey(info=info, material=material))
        return info

    def rotate(self, key_id: str | None = None) -> KeyInfo:
        """Generate a new key and make it the current issuing key."""
        key_id = key_id or self._new_id()
        self.add(key_id)
        return self.activate(key_id)

    def activate(self, key_id: str) -> KeyInfo:
        """Make a standby or retired key current and retire the old one."""
        target = self._require(key_id)
        if target.info.status == KeyStatus.REVOKED:
            raise JamKeyChainError(
                "A revoked key cannot be activated.",
                error_code="keychain.revoked_key",
            )
        current = self.current()
        if current is not None and current.id != key_id:
            self._set_status(current.id, KeyStatus.RETIRED)
        if target.info.status != KeyStatus.CURRENT:
            self._set_status(key_id, KeyStatus.CURRENT)
        return self.get(key_id)

    def retire(self, key_id: str) -> KeyInfo:
        """Stop issuing with a key while keeping it valid for verification."""
        key = self._require(key_id)
        if key.info.status == KeyStatus.CURRENT:
            raise JamKeyChainError(
                "Activate another key before retiring the current key.",
                error_code="keychain.current_key",
            )
        if key.info.status == KeyStatus.REVOKED:
            raise JamKeyChainError(
                "A revoked key cannot be retired.",
                error_code="keychain.revoked_key",
            )
        self._set_status(key_id, KeyStatus.RETIRED)
        return self.get(key_id)

    def revoke(self, key_id: str) -> KeyInfo:
        """Make a key unavailable for all future verification."""
        self._require(key_id)
        self._set_status(key_id, KeyStatus.REVOKED)
        return self.get(key_id)

    def remove(self, key_id: str) -> None:
        """Permanently remove a non-current key."""
        key = self._require(key_id)
        if key.info.status == KeyStatus.CURRENT:
            raise JamKeyChainError(
                "Activate another key before removing the current key.",
                error_code="keychain.current_key",
            )
        self._delete(key_id)

    def _material_for_issue(self) -> tuple[str, bytes]:
        """Return the current material for credential issuing."""
        current = self.current()
        if current is None:
            raise JamKeyChainError(
                "KeyChain has no current key.", error_code="keychain.no_current"
            )
        return current.id, self._require(current.id).material

    def _material_for_verify(self, key_id: str) -> bytes:
        """Return material for a non-revoked historical verification key."""
        key = self._require(key_id)
        if key.info.status == KeyStatus.REVOKED:
            raise JamKeyChainError(
                f"Key '{key_id}' has been revoked.",
                error_code="keychain.revoked_key",
            )
        return key.material

    def _set_status(self, key_id: str, status: KeyStatus) -> None:
        key = self._require(key_id)
        self._replace(
            _StoredKey(
                info=KeyInfo(
                    id=key.info.id,
                    status=status,
                    created_at=key.info.created_at,
                    algorithm=key.info.algorithm,
                    fingerprint=key.info.fingerprint,
                ),
                material=key.material,
            )
        )

    def _require(self, key_id: str) -> _StoredKey:
        key = self._load(key_id)
        if key is None:
            raise JamKeyChainError(
                f"Key '{key_id}' does not exist.", error_code="keychain.key_not_found"
            )
        return key

    def _generate_material(self) -> bytes:
        if self.algorithm.startswith("HS") or self.purpose == "local":
            return secrets.token_bytes(32)
        if self.algorithm.startswith("RS"):
            return generate_rsa_key_pair()["private"].encode()
        if self.algorithm.startswith("ES"):
            return generate_ecdsa_p384_keypair()["private"].encode()
        if self.algorithm in ("EDDSA", "ED25519"):
            return generate_ed25519_keypair()["private"].encode()
        raise JamKeyChainError(
            f"Cannot generate material for algorithm '{self.algorithm}'.",
            error_code="keychain.unsupported_algorithm",
        )

    @staticmethod
    def _fingerprint(material: bytes) -> str:
        return f"sha256:{hashlib.sha256(material).hexdigest()}"

    @staticmethod
    def _validate_id(key_id: str) -> None:
        if not key_id or "/" in key_id or "\\" in key_id or key_id in (".", ".."):
            raise JamKeyChainError(
                "Key ID must be a non-empty file-name-safe string.",
                error_code="keychain.invalid_key_id",
            )

    @staticmethod
    def _new_id() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S-") + secrets.token_hex(4)
