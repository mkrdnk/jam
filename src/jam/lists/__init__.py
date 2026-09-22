# -*- coding: utf-8 -*-

"""Token allowlists and denylists with pluggable storage backends."""

from typing import TYPE_CHECKING, Any

from jam.exceptions import JamConfigurationError
from jam.lists.__base__ import BaseList
from jam.lists.memory import MemoryList


if TYPE_CHECKING:
    from jam.lists.json import JSONList
    from jam.lists.redis import RedisList


# Compatibility with the pre-generic JWT list API.
BaseJWTList = BaseList


def build_list(list_config: dict[str, Any] | BaseList) -> BaseList:
    """Build a list instance from a config dict or return it as-is.

    Args:
        list_config (dict[str, Any] | BaseList): List config or list instance.

    Returns:
        BaseList: Built list instance.

    Raises:
        JamConfigurationError: If the backend is unknown.
    """
    if isinstance(list_config, BaseList):
        return list_config
    backend = list_config.get("backend")
    list_type = list_config.get("type", "black")
    if list_type not in ("black", "white"):
        raise JamConfigurationError(
            message=f"Unknown list type: {list_type}",
            error_code="configuration.lists.unknown_type",
        )
    match backend:
        case "redis":
            from jam.lists.redis import RedisList

            return RedisList(
                type=list_type,
                prefix=list_config.get("prefix", "jwt_list"),
                redis_uri=list_config.get("redis_uri"),
                ttl=list_config.get("ttl"),
            )
        case "json":
            from jam.lists.json import JSONList

            return JSONList(
                type=list_type,
                prefix=list_config.get("prefix", "jwt_list"),
                json_path=list_config.get("json_path", "whitelist.json"),
            )
        case "memory":
            return MemoryList(
                type=list_type,
                prefix=list_config.get("prefix", "jwt_list"),
            )
        case _:
            raise JamConfigurationError(
                message=f"Unknown list backend: {backend}",
                error_code="configuration.lists.unknown_backend",
            )


def __getattr__(name: str) -> Any:
    """Load optional list backends only when explicitly requested."""
    if name == "JSONList":
        from jam.lists.json import JSONList

        return JSONList
    if name == "RedisList":
        from jam.lists.redis import RedisList

        return RedisList
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseList",
    "BaseJWTList",
    "JSONList",
    "MemoryList",
    "RedisList",
    "build_list",
]
