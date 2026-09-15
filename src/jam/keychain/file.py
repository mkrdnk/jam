# -*- coding: utf-8 -*-

"""Filesystem-backed KeyChain implementation."""

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import stat
import tempfile

from jam.exceptions import JamKeyChainError

from .__base__ import BaseKeyChain, KeyInfo, KeyStatus, _StoredKey


class FileStorage(BaseKeyChain):
    """Persist every key in an owner-only directory."""

    __CURRENT_NAME: str = "current.jam"
    __LOCK: str = "jam.lock"

    def __init__(
        self, path: str | Path, algorithm: str, purpose: str | None = None
    ) -> None:
        """Open or create a persistent chain at ``path``."""
        super().__init__(algorithm=algorithm, purpose=purpose)
        self.path = Path(path)
        self._prepare_directory()

    def _prepare_directory(self) -> None:
        if self.path.is_symlink():
            raise JamKeyChainError("Storage path must not be a symlink.")
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink() or not self.path.is_dir():
            raise JamKeyChainError("Storage path must be a regular directory.")
        if self.path.stat().st_uid != os.geteuid():
            raise JamKeyChainError(
                "Storage directory must be owned by the current user.",
                error_code="keychain.ownership",
            )
        os.chmod(self.path, 0o700)
        self._check_mode(self.path, 0o700)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        import fcntl

        lock = self.path / self.__LOCK
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _key_path(self, key_id: str) -> Path:
        self._validate_id(key_id)
        return self.path / f"{key_id}.json"

    def _load(self, key_id: str) -> _StoredKey | None:
        with self._locked():
            path = self._key_path(key_id)
            if not path.exists():
                return None
            self._check_regular_file(path)
            try:
                data = json.loads(path.read_text())
                material = base64.b64decode(data["material"], validate=True)
                info = KeyInfo(
                    id=data["id"],
                    status=KeyStatus(data["status"]),
                    created_at=datetime.fromisoformat(data["created_at"]),
                    algorithm=data["algorithm"],
                    fingerprint=data["fingerprint"],
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise JamKeyChainError(
                    f"Key file '{path.name}' is corrupt.",
                    error_code="keychain.corrupt_key",
                ) from exc
            if info.id != key_id or self._fingerprint(material) != info.fingerprint:
                raise JamKeyChainError(
                    f"Key file '{path.name}' failed integrity validation.",
                    error_code="keychain.corrupt_key",
                )
            return _StoredKey(info=info, material=material)

    def _save(self, key: _StoredKey) -> None:
        with self._locked():
            path = self._key_path(key.info.id)
            if path.exists():
                raise JamKeyChainError(
                    f"Key '{key.info.id}' already exists.",
                    error_code="keychain.duplicate_key",
                )
            self._write(path, key)

    def _replace(self, key: _StoredKey) -> None:
        with self._locked():
            path = self._key_path(key.info.id)
            if not path.exists():
                raise JamKeyChainError(error_code="keychain.key_not_found")
            self._check_regular_file(path)
            self._write(path, key)
            if key.info.status == KeyStatus.CURRENT:
                self._write_current(key.info.id)
            elif key.info.status == KeyStatus.REVOKED:
                current = self.path / self.__CURRENT_NAME
                if current.exists():
                    self._check_regular_file(current)
                    if current.read_text().strip() == key.info.id:
                        current.unlink()
                        self._fsync_directory()

    def _delete(self, key_id: str) -> None:
        with self._locked():
            path = self._key_path(key_id)
            self._check_regular_file(path)
            path.unlink()
            self._fsync_directory()

    def _all(self) -> list[_StoredKey]:
        with self._locked():
            paths = list(self.path.glob("*.json"))
        keys: list[_StoredKey] = []
        for path in paths:
            key = self._load(path.stem)
            if key is not None:
                keys.append(key)
        return keys

    def current(self) -> KeyInfo | None:
        """Resolve the current key through the durable pointer."""
        pointer = self.path / self.__CURRENT_NAME
        if not pointer.exists():
            current = super().current()
            if current is not None:
                raise JamKeyChainError(
                    "Current key pointer is missing.",
                    error_code="keychain.invalid_current",
                )
            return None
        self._check_regular_file(pointer)
        key_id = pointer.read_text().strip()
        try:
            key = self._require(key_id)
        except JamKeyChainError as exc:
            raise JamKeyChainError(
                "Current key pointer references a missing key.",
                error_code="keychain.invalid_current",
            ) from exc
        if key.info.status != KeyStatus.CURRENT:
            raise JamKeyChainError(
                "Current key pointer references a non-current key.",
                error_code="keychain.invalid_current",
            )
        return key.info

    def _write(self, path: Path, key: _StoredKey) -> None:
        data = {
            "id": key.info.id,
            "status": key.info.status.value,
            "created_at": key.info.created_at.isoformat(),
            "algorithm": key.info.algorithm,
            "fingerprint": key.info.fingerprint,
            "material": base64.b64encode(key.material).decode("ascii"),
        }
        fd, temporary = tempfile.mkstemp(dir=self.path, prefix=".key-", text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as file:
                json.dump(data, file, separators=(",", ":"))
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
            self._fsync_directory()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _write_current(self, key_id: str) -> None:
        """Atomically update the non-secret pointer to the issuing key."""
        fd, temporary = tempfile.mkstemp(dir=self.path, prefix=".current-", text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as file:
                file.write(key_id + "\n")
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.path / self.__CURRENT_NAME)
            self._fsync_directory()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _fsync_directory(self) -> None:
        fd = os.open(self.path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _check_mode(path: Path, expected: int) -> None:
        if stat.S_IMODE(path.stat().st_mode) != expected:
            raise JamKeyChainError(
                f"Unsafe permissions on '{path}'.", error_code="keychain.permissions"
            )

    def _check_regular_file(self, path: Path) -> None:
        if path.is_symlink() or not path.is_file():
            raise JamKeyChainError(
                f"Key path '{path.name}' is not a regular file.",
                error_code="keychain.unsafe_path",
            )
        if path.stat().st_uid != os.geteuid():
            raise JamKeyChainError(
                f"Key path '{path.name}' must be owned by the current user.",
                error_code="keychain.ownership",
            )
        self._check_mode(path, 0o600)
