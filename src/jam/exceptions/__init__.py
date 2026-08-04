# -*- coding: utf-8 -*-

"""All Jam exceptions"""

from .base import JamConfigurationError, JamError, JamValidationError
from .jose import (
    JamJWEEncryptionError,
    JamJWEDecryptionError,
    JamJWKValidationError,
    JamJWSVerificationError,
)
from .jwt import (
    JamJWTExpired,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamJWTNotYetValid,
    JamJWTUnsupportedAlgorithm,
)
from .oauth2 import (
    JamOAuth2EmptyRaw,
    JamOAuth2Error,
    JamOAuth2ProviderNotConfigured,
)
from .paseto import (
    JamPASETOInvalidED25519Key,
    JamPASETOInvalidPurpose,
    JamPASETOInvalidRSAKey,
    JamPASETOInvalidSecp384r1Key,
    JamPASETOInvalidSymmetricKey,
    JamPASETOInvalidTokenFormat,
    JamPASETOKeyVerificationError,
)
from .plugins import (
    JamFlaskPluginConfigError,
    JamFlaskPluginError,
    JamLitestarPluginConfigError,
    JamLitestarPluginError,
    JamStarlettePluginConfigError,
    JamStarlettePluginError,
)
from .sessions import (
    JamSessionEmptyAESKey,
    JamSessionNotFound,
)
from .saml import (
    JamSAMLError,
    JamSAMLExpired,
    JamSAMLNotYetValid,
    JamSAMLInvalidAudience,
    JamSAMLInvalidIssuer,
    JamSAMLEmptyPrivateKey,
    JamSAMLEmptyPublicKey,
    JamSAMLUnsupportedAlgorithm,
    JamSAMLValidationError,
)


__all__ = [
    "JamError",
    "JamConfigurationError",
    "JamValidationError",
    "JamOAuth2Error",
    "JamOAuth2EmptyRaw",
    "JamOAuth2ProviderNotConfigured",
    "JamJWTExpired",
    "JamJWTInBlackList",
    "JamJWTNotInWhiteList",
    "JamJWTNotYetValid",
    "JamJWTUnsupportedAlgorithm",
    "JamJWSVerificationError",
    "JamJWKValidationError",
    "JamJWEEncryptionError",
    "JamJWEDecryptionError",
    "JamPASETOInvalidSymmetricKey",
    "JamPASETOInvalidRSAKey",
    "JamPASETOInvalidED25519Key",
    "JamPASETOInvalidSecp384r1Key",
    "JamPASETOInvalidPurpose",
    "JamPASETOInvalidTokenFormat",
    "JamPASETOKeyVerificationError",
    "JamLitestarPluginConfigError",
    "JamLitestarPluginError",
    "JamFlaskPluginConfigError",
    "JamFlaskPluginError",
    "JamStarlettePluginConfigError",
    "JamStarlettePluginError",
    "JamSessionNotFound",
    "JamSessionEmptyAESKey",
    "JamSAMLError",
    "JamSAMLExpired",
    "JamSAMLNotYetValid",
    "JamSAMLInvalidAudience",
    "JamSAMLInvalidIssuer",
    "JamSAMLEmptyPrivateKey",
    "JamSAMLEmptyPublicKey",
    "JamSAMLUnsupportedAlgorithm",
    "JamSAMLValidationError",
]
