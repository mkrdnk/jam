# -*- coding: utf-8 -*-

"""Django Modern REST integration for Jam."""

from jam.ext import CredentialSource
from jam.ext.django.dmr.authentication import JamAsyncAuth, JamSyncAuth
from jam.ext.django.dmr.authorization import authorize, request_principal


__all__ = [
    "CredentialSource",
    "JamAsyncAuth",
    "JamSyncAuth",
    "authorize",
    "request_principal",
]
