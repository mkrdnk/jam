# -*- coding: utf-8 -*-

"""Flask authentication and authorization integration."""

from jam.ext._base import CredentialSource
from jam.ext.flask.auth import JamAuth, current_principal, get_jam


__all__ = ["CredentialSource", "JamAuth", "current_principal", "get_jam"]
