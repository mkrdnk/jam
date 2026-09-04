# -*- coding: utf-8 -*-

from .base import JamError


class JamKeyChainError(JamError):
    """KeyChain operation could not be completed."""

    default_code = "keychain.error"
