# -*- coding: utf-8 -*-

"""
Async module for making server auth sessions.
"""

import os
from typing import Any, Callable, Optional
from uuid import uuid4

from jam.aio.sessions.__base__ import BaseAsyncSessionModule
from jam.encoders import BaseEncoder, JsonEncoder


def create_instance(
    session_type: str | None = None,
    sessions_type: str | None = None,
    serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
    **kwargs: Any,
) -> BaseAsyncSessionModule:
    """Create async session module instance.

    Args:
        session_type: "redis" | "json" | "custom"
        sessions_type: Alias for session_type (deprecated, use 'session_type')
        serializer: JSON encoder/decoder
        **kwargs: Config params specific to session type

    Returns:
        BaseSessionModule instance (async-compatible)
    """
    # Handle backward compatibility: sessions_type -> session_type
    if session_type is None and sessions_type is not None:
        session_type = sessions_type
    elif session_type is None:
        raise ValueError(
            "Either 'session_type' or 'sessions_type' must be provided"
        )
    # Get optional params
    id_factory: Callable[[], str] = kwargs.get(
        "id_factory", lambda: str(uuid4())
    )
    is_session_crypt: bool = kwargs.get("is_session_crypt", False)
    session_aes_secret: Optional[bytes] = kwargs.get("session_aes_secret")

    # Handle env variable for AES secret
    if session_aes_secret is None:
        env_secret = os.getenv("JAM_SESSION_AES_SECRET")
        if env_secret:
            session_aes_secret = (
                env_secret.encode()
                if isinstance(env_secret, str)
                else env_secret
            )

    if session_type == "redis":
        from jam.aio.sessions.redis import RedisSessions

        return RedisSessions(
            redis_uri=kwargs.get("redis_uri", "redis://localhost:6379/0"),
            redis_sessions_key=kwargs.get("redis_sessions_key", "sessions"),
            default_ttl=kwargs.get("default_ttl"),
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            id_factory=id_factory,
            serializer=serializer,
        )
    elif session_type == "json":
        from jam.aio.sessions.json import JSONSessions

        return JSONSessions(
            json_path=kwargs.get("json_path", "sessions.json"),
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            id_factory=id_factory,
            serializer=serializer,
        )
    elif session_type == "custom":
        from jam.utils.config_maker import __module_loader__

        custom_module = kwargs.get("custom_module")
        if not custom_module:
            raise ValueError(
                "custom_module must be specified for session_type='custom'"
            )
        module_cls = __module_loader__(custom_module)
        return module_cls(
            is_session_crypt=is_session_crypt,
            session_aes_secret=session_aes_secret,
            id_factory=id_factory,
            serializer=serializer,
            **{
                k: v
                for k, v in kwargs.items()
                if k
                not in ["session_type", "custom_module", "logger", "serializer"]
            },
        )
    else:
        raise ValueError(f"Unknown session_type: {session_type}")


__all__ = ["create_instance"]
