# -*- coding: utf-8 -*-

from .base import JamError, JamConfigurationError


class JamSessionNotFound(JamError):
    default_message = "Session not found."
    default_code = "sessions.not_found"


class JamSessionEmptyAESKey(JamConfigurationError):
    default_message = "Session AES key is empty."
    default_code = "sessions.empty_aes_key"
