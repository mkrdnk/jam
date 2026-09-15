# -*- coding: utf-8 -*-

"""Module for managing JWT black and white lists."""

from typing import Any

from jam.exceptions import JamConfigurationError
from jam.lists.__base__ import BaseList
from jam.lists.json import JSONList
from jam.lists.memory import MemoryList
from jam.lists.redis import RedisList


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
    backend = list_config["backend"]
    match backend:
        case "redis":
            return RedisList(
                type=list_config.get("type", "black"),
                prefix=list_config.get("prefix", "jwt_list"),
                redis_uri=list_config.get("redis_uri"),
                ttl=list_config.get("ttl"),
            )
        case "json":
            return JSONList(
                type=list_config.get("type", "black"),
                prefix=list_config.get("prefix", "jwt_list"),
                json_path=list_config.get("json_path", "whitelist.json"),
            )
        case "memory":
            return MemoryList(
                type=list_config.get("type", "black"),
                prefix=list_config.get("prefix", "jwt_list"),
            )
        case _:
            raise JamConfigurationError(
                message=f"Unknown list backend: {backend}",
                error_code="configuration.lists.unknown_backend",
            )


__all__ = [
    "BaseList",
    "BaseJWTList",
    "JSONList",
    "MemoryList",
    "RedisList",
    "build_list",
]
