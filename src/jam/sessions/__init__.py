# -*- coding: utf-8 -*-

"""
Module for making server auth sessions.
"""

from typing import Any

from .__base__ import BaseSessionModule
from .json import JSONSessions
from .redis import RedisSessions


REGISTRY: dict[str, type[BaseSessionModule]] = {
    "redis": RedisSessions,
    "json": JSONSessions,
}


__all__ = [
    "BaseSessionModule",
    "RedisSessions",
    "JSONSessions",
    "REGISTRY",
]
