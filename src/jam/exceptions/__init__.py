# -*- coding: utf-8 -*-

"""All Jam exceptions"""

from .base import JamConfigurationError, JamError, JamValidationError
from .jose import (
    JamJWEDecryptionError,
    JamJWEEncryptionError,
    JamJWKValidationError,
    JamJWSVerificationError,
)
from .jwt import (
    JamJWTExpired,
    JamJWTInBlackList,
    JamJWTInvalidClaim,
    JamJWTNotInWhiteList,
    JamJWTNotYetValid,
    JamJWTUnsupportedAlgorithm,
)
from .keychain import JamKeyChainError
from .lists import JamTokenInDenyList, JamTokenNotInAllowList
from .macaroons import (
    InvalidCaveatError,
    MacaroonError,
    SerializationError,
    VerificationError,
)
from .oauth2 import (
    JamOAuth2EmptyRaw,
    JamOAuth2Error,
    JamOAuth2ProviderNotConfigured,
)
from .paseto import (
    JamPASETOImplicitAssertionUnsupported,
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
from .saml import (
    JamSAMLEmptyPrivateKey,
    JamSAMLEmptyPublicKey,
    JamSAMLError,
    JamSAMLExpired,
    JamSAMLInvalidAudience,
    JamSAMLInvalidIssuer,
    JamSAMLInvalidRecipient,
    JamSAMLNotYetValid,
    JamSAMLReplayDetected,
    JamSAMLSOAPError,
    JamSAMLUnsupportedAlgorithm,
    JamSAMLValidationError,
)
from .sessions import (
    JamSessionEmptyAESKey,
    JamSessionExpired,
    JamSessionInvalidClaim,
    JamSessionNotFound,
    JamSessionNotYetValid,
)


__all__ = [
    "MacaroonError",
    "SerializationError",
    "VerificationError",
    "InvalidCaveatError",
    "JamError",
    "JamConfigurationError",
    "JamValidationError",
    "JamOAuth2Error",
    "JamOAuth2EmptyRaw",
    "JamOAuth2ProviderNotConfigured",
    "JamJWTExpired",
    "JamJWTInBlackList",
    "JamJWTInvalidClaim",
    "JamJWTNotInWhiteList",
    "JamJWTNotYetValid",
    "JamJWTUnsupportedAlgorithm",
    "JamTokenInDenyList",
    "JamTokenNotInAllowList",
    "JamJWSVerificationError",
    "JamJWKValidationError",
    "JamJWEEncryptionError",
    "JamJWEDecryptionError",
    "JamKeyChainError",
    "JamPASETOInvalidSymmetricKey",
    "JamPASETOInvalidRSAKey",
    "JamPASETOInvalidED25519Key",
    "JamPASETOInvalidSecp384r1Key",
    "JamPASETOInvalidPurpose",
    "JamPASETOImplicitAssertionUnsupported",
    "JamPASETOInvalidTokenFormat",
    "JamPASETOKeyVerificationError",
    "JamLitestarPluginConfigError",
    "JamLitestarPluginError",
    "JamFlaskPluginConfigError",
    "JamFlaskPluginError",
    "JamStarlettePluginConfigError",
    "JamStarlettePluginError",
    "JamSessionNotFound",
    "JamSessionExpired",
    "JamSessionNotYetValid",
    "JamSessionInvalidClaim",
    "JamSessionEmptyAESKey",
    "JamSAMLError",
    "JamSAMLExpired",
    "JamSAMLNotYetValid",
    "JamSAMLInvalidAudience",
    "JamSAMLInvalidIssuer",
    "JamSAMLInvalidRecipient",
    "JamSAMLReplayDetected",
    "JamSAMLSOAPError",
    "JamSAMLEmptyPrivateKey",
    "JamSAMLEmptyPublicKey",
    "JamSAMLUnsupportedAlgorithm",
    "JamSAMLValidationError",
]
