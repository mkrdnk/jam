# -*- coding: utf-8 -*-

"""Asynchronous JWT allowlists and denylists."""

from typing import Any

from jam.aio.lists.__base__ import BaseAsyncList
from jam.exceptions import JamConfigurationError


def build_list(
    list_config: dict[str, Any] | BaseAsyncList,
) -> BaseAsyncList:
    """Build an asynchronous token list."""
    if isinstance(list_config, BaseAsyncList):
        return list_config

    backend = list_config["backend"]
    list_type = list_config.get("type", "black")
    prefix = list_config.get("prefix", "jwt_list")
    if list_type not in ("black", "white"):
        raise JamConfigurationError(
            message=f"Unknown async list type: {list_type}",
            error_code="configuration.lists.unknown_type",
        )
    match backend:
        case "memory":
            from jam.aio.lists.memory import MemoryList

            return MemoryList(type=list_type, prefix=prefix)
        case "redis":
            from jam.aio.lists.redis import RedisList

            return RedisList(
                type=list_type,
                prefix=prefix,
                redis_uri=list_config.get("redis_uri"),
                ttl=list_config.get("ttl"),
            )
        case "json":
            from jam.aio.lists.json import AsyncJSONList

            return AsyncJSONList(
                type=list_type,
                prefix=prefix,
                json_path=list_config.get("json_path", "whitelist.json"),
            )
        case _:
            raise JamConfigurationError(
                message=f"Unknown async list backend: {backend}",
                error_code="configuration.lists.unknown_backend",
            )


__all__ = ["BaseAsyncList", "build_list"]
