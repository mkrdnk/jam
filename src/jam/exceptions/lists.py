# -*- coding: utf-8 -*-

"""Generic token-list errors."""

from .base import JamError


class JamTokenInDenyList(JamError):
    """A token is present in its configured denylist."""

    default_message = "Token is in the denylist."
    # Retain the pre-generic code for compatibility.
    default_code = "jwt.blacklist"


class JamTokenNotInAllowList(JamError):
    """A token is absent from its configured allowlist."""

    default_message = "Token is not in the allowlist."
    # Retain the pre-generic code for compatibility.
    default_code = "jwt.whitelist"


__all__ = ["JamTokenInDenyList", "JamTokenNotInAllowList"]
