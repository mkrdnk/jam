# -*- coding: utf-8 -*-

from .base import JamConfigurationError, JamError, JamValidationError


class JamPASETOInvalidSymmetricKey(JamConfigurationError):
    default_message = "Invalid symmetric key."
    default_code = "paseto.configuration.invalid_symmetric_key"


class JamPASETOInvalidRSAKey(JamConfigurationError):
    default_message = "Invalid RSA key."
    default_code = "paseto.configuration.invalid_rsa_key"


class JamPASETOInvalidED25519Key(JamConfigurationError):
    default_message = "Invalid ED25519 key."
    default_code = "paseto.configuration.invalid_ed25519_key"


class JamPASETOInvalidSecp384r1Key(JamConfigurationError):
    default_message = "Invalid SECP384R1 key."
    default_code = "paseto.configuration.invalid_secp384r1_key"


class JamPASETOInvalidPurpose(JamConfigurationError):
    default_message = "Invalid purpose."
    default_code = "paseto.configuration.invalid_purpose"


class JamPASETOImplicitAssertionUnsupported(JamValidationError):
    """Raised when a PASETO version cannot authenticate an assertion."""

    default_message = (
        "This PASETO version does not support implicit assertions."
    )
    default_code = "paseto.validation.implicit_assertion_unsupported"


class JamPASETOExpired(JamValidationError):
    """Raised when a PASETO has passed its expiration time."""

    default_message = "PASETO lifetime expired."
    default_code = "paseto.token_expired"


class JamPASETONotYetValid(JamValidationError):
    """Raised when a PASETO is used before its validity window."""

    default_message = "PASETO is not yet valid."
    default_code = "paseto.token_not_yet_valid"


class JamPASETOInvalidClaim(JamValidationError):
    """Raised when a PASETO registered claim has an invalid value."""

    default_message = "PASETO claim has an invalid value."
    default_code = "paseto.invalid_claim"


class JamPASETOInvalidTokenFormat(JamValidationError):
    default_message = "Invalid token format."
    default_code = "paseto.validation.invalid_token_format"


class JamPASETOKeyVerificationError(JamError):
    default_message = "Key verification failed."
    default_code = "paseto.key_verification_failed"
