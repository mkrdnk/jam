# -*- coding: utf-8 -*-

"""Module for managing JWT black and white lists.

Deprecated: lists now live in `jam.lists`. These names are kept as
aliases for backward compatibility.
"""

from jam.lists.__base__ import BaseList as BaseJWTList
from jam.lists.json import JSONList
from jam.lists.memory import MemoryList
from jam.lists.redis import RedisList
from jam.lists.__base__ import BaseList


__all__ = [
    "BaseJWTList",
    "BaseList",
    "JSONList",
    "MemoryList",
    "RedisList",
]
