# -*- coding: utf-8 -*-

"""Litestar authentication and authorization integration."""

from jam.ext._base import CredentialSource
from jam.ext.litestar.plugin import (
    JamAuthenticationMiddleware,
    JamPlugin,
    permission_guard,
)


__all__ = [
    "CredentialSource",
    "JamAuthenticationMiddleware",
    "JamPlugin",
    "permission_guard",
]
