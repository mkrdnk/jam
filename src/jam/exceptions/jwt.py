# -*- coding: utf-8 -*-

from .base import JamConfigurationError, JamError, JamValidationError
from .lists import JamTokenInDenyList, JamTokenNotInAllowList


class JamJWTExpired(JamError):
    default_message = "Token lifetime expired."
    default_code = "jwt.token_expired"


class JamJWTNotYetValid(JamError):
    default_message = "Token is not yet valid (nbf claim)."
    default_code = "jwt.token_not_yet_valid"


class JamJWTInvalidClaim(JamValidationError):
    """Raised when a JWT claim has an invalid value."""

    default_message = "JWT claim has an invalid value."
    default_code = "jwt.invalid_claim"


# Compatibility aliases for the original JWT-specific API.
JamJWTInBlackList = JamTokenInDenyList
JamJWTNotInWhiteList = JamTokenNotInAllowList


class JamJWTUnsupportedAlgorithm(JamConfigurationError):
    default_message = "Unsupported JWT algorithm."
    default_code = "jwt.config.unsupported_algorithm"
