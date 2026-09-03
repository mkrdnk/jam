# -*- coding: utf-8 -*-

"""Starlette authentication integration."""

from jam.ext._base import CredentialSource
from jam.ext.starlette.auth import JamAuthBackend, JamUser


__all__ = ["CredentialSource", "JamAuthBackend", "JamUser"]
