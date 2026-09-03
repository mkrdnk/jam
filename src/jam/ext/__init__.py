# -*- coding: utf-8 -*-

"""Framework integrations built around one configured :class:`jam.Jam`.

Framework packages are intentionally not imported here, so installing Jam does
not require optional web-framework dependencies.
"""

from jam.ext._base import AuthenticationResult, CredentialSource


__all__ = ["AuthenticationResult", "CredentialSource"]
