# -*- coding: utf-8 -*-

"""
Module for making server auth sessions.
"""

from collections.abc import Iterator, MutableMapping
from importlib import import_module
from typing import TYPE_CHECKING, cast

from .__base__ import BaseSessionModule


if TYPE_CHECKING:
    from .json import JSONSessions
    from .redis import RedisSessions


class _SessionRegistry(MutableMapping[str, type[BaseSessionModule]]):
    """Resolve optional session backends only when they are selected."""

    _BACKEND_PATHS: dict[str, tuple[str, str]] = {
        "redis": ("jam.sessions.redis", "RedisSessions"),
        "json": ("jam.sessions.json", "JSONSessions"),
    }

    def __init__(self) -> None:
        """Initialize the known backend names without importing them."""
        self._backends: dict[str, type[BaseSessionModule] | tuple[str, str]] = (
            dict(self._BACKEND_PATHS)
        )

    def __getitem__(self, name: str) -> type[BaseSessionModule]:
        """Return the selected backend class, importing it on first access."""
        backend = self._backends[name]
        if isinstance(backend, tuple):
            module_name, class_name = backend
            module = import_module(module_name)
            backend = cast(
                type[BaseSessionModule], getattr(module, class_name)
            )
            self._backends[name] = backend
        return backend

    def __setitem__(
        self,
        name: str,
        backend: type[BaseSessionModule],
    ) -> None:
        """Register or replace a session backend."""
        self._backends[name] = backend

    def __delitem__(self, name: str) -> None:
        """Remove a registered session backend."""
        del self._backends[name]

    def __iter__(self) -> Iterator[str]:
        """Iterate over registered backend names without importing them."""
        return iter(self._backends)

    def __len__(self) -> int:
        """Return the number of registered session backends."""
        return len(self._backends)

    def copy(self) -> dict[str, type[BaseSessionModule]]:
        """Return a concrete registry copy, resolving each backend."""
        return {name: self[name] for name in self}


REGISTRY = _SessionRegistry()


def __getattr__(name: str) -> type[BaseSessionModule]:
    """Lazily expose optional session backend classes."""
    backend_paths = _SessionRegistry._BACKEND_PATHS
    for module_name, class_name in backend_paths.values():
        if name == class_name:
            module = import_module(module_name)
            backend = cast(
                type[BaseSessionModule], getattr(module, class_name)
            )
            globals()[name] = backend
            return backend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseSessionModule",
    "RedisSessions",
    "JSONSessions",
    "REGISTRY",
]
