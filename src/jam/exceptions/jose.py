# -*- coding: utf-8 -*-

from .base import JamConfigurationError, JamValidationError


class JamJWSVerificationError(JamValidationError):
    default_message = "JWS signature verification failed."
    default_code = "jws.verification_error"


class JamJWSValidationError(JamValidationError):
    default_message = "JWS validation failed."
    default_code = "jws.validation_error"


class JamJWSInvalidFormatError(JamValidationError):
    default_message = "Invalid JWS format."
    default_code = "jws.invalid_format"


class JamJWSSigningError(JamValidationError):
    default_message = "JWS signing failed."
    default_code = "jws.signing_error"


class JamJWKValidationError(JamValidationError):
    default_message = "JWK validation failed."
    default_code = "jwk.validation_error"


class JamJWKInvalidKeyTypeError(JamValidationError):
    default_message = "Unsupported JWK key type."
    default_code = "jwk.invalid_key_type"


class JamJWEEncryptionError(JamValidationError):
    default_message = "JWE encryption failed."
    default_code = "jwe.encryption_error"


class JamJWEDecryptionError(JamValidationError):
    default_message = "JWE decryption failed."
    default_code = "jwe.decryption_error"


class JamJWEInvalidFormatError(JamValidationError):
    default_message = "Invalid JWE format."
    default_code = "jwe.invalid_format"


class JamInvalidKeyTypeError(JamConfigurationError):
    default_message = "Invalid key type."
    default_code = "jose.invalid_key_type"


class JamAlgorithmError(JamConfigurationError):
    default_message = "Algorithm error."
    default_code = "jose.algorithm_error"


class JamInvalidPaddingError(JamValidationError):
    default_message = "Invalid padding."
    default_code = "jose.invalid_padding"


class JamRedisListConfigurationError(JamConfigurationError):
    default_message = "Redis list configuration error."
    default_code = "jose.redis_list_configuration_error"
