# -*- coding: utf-8 -*-

"""In-memory KeyChain implementation."""

from .__base__ import BaseKeyChain, _StoredKey


class Memory(BaseKeyChain):
    """Keep key material and lifecycle metadata in process memory."""

    def __init__(self, algorithm: str, purpose: str | None = None) -> None:
        """Initialize an empty in-process chain."""
        super().__init__(algorithm=algorithm, purpose=purpose)
        self._keys: dict[str, _StoredKey] = {}

    def _load(self, key_id: str) -> _StoredKey | None:
        return self._keys.get(key_id)

    def _save(self, key: _StoredKey) -> None:
        self._keys[key.info.id] = key

    def _replace(self, key: _StoredKey) -> None:
        self._keys[key.info.id] = key

    def _delete(self, key_id: str) -> None:
        del self._keys[key_id]

    def _all(self) -> list[_StoredKey]:
        return list(self._keys.values())
