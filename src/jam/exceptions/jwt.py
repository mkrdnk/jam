# -*- coding: utf-8 -*-

from .base import JamConfigurationError, JamError


class JamJWTExpired(JamError):
    default_message = "Token lifetime expired."
    default_code = "jwt.token_expired"


class JamJWTNotYetValid(JamError):
    default_message = "Token is not yet valid (nbf claim)."
    default_code = "jwt.token_not_yet_valid"


class JamJWTInBlackList(JamError):
    default_message = "Token in blacklist."
    default_code = "jwt.blacklist"


class JamJWTNotInWhiteList(JamError):
    default_message = "Token not in whitelist."
    default_code = "jwt.whitelist"


class JamJWTUnsupportedAlgorithm(JamConfigurationError):
    default_message = "Unsupported JWT algorithm."
    default_code = "jwt.config.unsupported_algorithm"
