# Exceptions

Jam exceptions provide a stable machine-readable code in addition to a
human-readable message. Use the code when your application needs to identify
an error; messages may contain context intended for logs or users.

```python
from jam.exceptions import JamError

try:
    principal = jam.authenticate(token, via="jwt")
except JamError as exc:
    print(exc.error_code)
    print(exc.message)
    print(exc.details)
```

Every Jam exception derives from `JamError` and exposes:

| Attribute | Description |
| --- | --- |
| `error_code` | Stable machine-readable error identifier. |
| `message` | Human-readable explanation of the error. |
| `details` | Optional additional context. |

The string representation includes all available information:

```text
[jwt.token_expired] Token lifetime expired.
```

The tables below list the default code for every exception class. A caller may
supply a more specific `error_code` when raising a base exception, so always
read the code from the caught exception rather than from the class attribute.

## Base exceptions

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamError` | `jam.error` | Base class for all Jam exceptions. |
| `JamValidationError` | `jam.validation` | Input, credential, or protocol validation failed. |
| `JamConfigurationError` | `jam.configuration` | Jam or one of its modules is configured incorrectly. |

Catch `JamConfigurationError` for setup problems, `JamValidationError` for
invalid data, or `JamError` when one handler should cover every Jam failure.

## JOSE

These exceptions cover JWS, JWK, and JWE operations. They are defined in
`jam.exceptions.jose`; commonly used classes are also exported from
`jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamJWSVerificationError` | `jws.verification_error` | JWS signature verification failed. |
| `JamJWSValidationError` | `jws.validation_error` | JWS validation failed. |
| `JamJWSInvalidFormatError` | `jws.invalid_format` | The JWS has an invalid format. |
| `JamJWSSigningError` | `jws.signing_error` | JWS signing failed. |
| `JamJWKValidationError` | `jwk.validation_error` | JWK validation failed. |
| `JamJWKInvalidKeyTypeError` | `jwk.invalid_key_type` | The JWK key type is unsupported. |
| `JamJWEEncryptionError` | `jwe.encryption_error` | JWE encryption failed. |
| `JamJWEDecryptionError` | `jwe.decryption_error` | JWE decryption failed. |
| `JamJWEInvalidFormatError` | `jwe.invalid_format` | The JWE has an invalid format. |
| `JamInvalidKeyTypeError` | `jose.invalid_key_type` | A JOSE key has an invalid type. |
| `JamAlgorithmError` | `jose.algorithm_error` | A JOSE algorithm is invalid or unsupported. |
| `JamInvalidPaddingError` | `jose.invalid_padding` | Cryptographic padding is invalid. |
| `JamRedisListConfigurationError` | `jose.redis_list_configuration_error` | A Redis-backed token list is configured incorrectly. |

## JWT

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamJWTExpired` | `jwt.token_expired` | The token lifetime has expired. |
| `JamJWTNotYetValid` | `jwt.token_not_yet_valid` | The token is not valid yet according to its `nbf` claim. |
| `JamJWTInBlackList` | `jwt.blacklist` | The token is present in the blacklist. |
| `JamJWTNotInWhiteList` | `jwt.whitelist` | The token is absent from the whitelist. |
| `JamJWTUnsupportedAlgorithm` | `jwt.config.unsupported_algorithm` | The configured JWT algorithm is unsupported. |

## KeyChain

Import `JamKeyChainError` from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamKeyChainError` | `keychain.error` | A KeyChain operation could not be completed. |

KeyChain operations use more specific codes on `JamKeyChainError`:

| Code | Description |
| --- | --- |
| `keychain.corrupt_key` | A stored key is corrupt or failed integrity validation. |
| `keychain.current_key` | An operation cannot be performed on the current key. |
| `keychain.duplicate_key` | A key with the same ID already exists. |
| `keychain.invalid_current` | The current-key state or pointer is invalid. |
| `keychain.invalid_key_id` | The key ID is empty or unsafe for use as a file name. |
| `keychain.key_not_found` | The requested key does not exist. |
| `keychain.no_current` | The KeyChain has no current key. |
| `keychain.ownership` | Key storage has unsafe ownership. |
| `keychain.permissions` | Key storage has unsafe permissions. |
| `keychain.revoked_key` | The operation is not allowed for a revoked key. |
| `keychain.unsafe_path` | A key path is not a regular file. |
| `keychain.unsupported_algorithm` | Key material cannot be generated for the configured algorithm. |

## Macaroons

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `MacaroonError` | `macaroon.validation` | Base error for macaroon validation. |
| `SerializationError` | `macaroon.serialization` | The macaroon transport is malformed or too large. |
| `VerificationError` | `macaroon.verification` | A signature, discharge graph, or predicate is invalid. |
| `InvalidCaveatError` | `macaroon.invalid_caveat` | A structured caveat is unknown or malformed. |

## OAuth2

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamOAuth2Error` | `oauth2.runtime_error` | An OAuth2 operation failed. |
| `JamOAuth2EmptyRaw` | `oauth2.empty_response` | The token endpoint returned an empty response. |
| `JamOAuth2ProviderNotConfigured` | `oauth2.configuration.provider_not_configured` | The requested OAuth2 provider is not configured. |

## PASETO

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamPASETOInvalidSymmetricKey` | `paseto.configuration.invalid_symmetric_key` | The symmetric PASETO key is invalid. |
| `JamPASETOInvalidRSAKey` | `paseto.configuration.invalid_rsa_key` | The RSA PASETO key is invalid. |
| `JamPASETOInvalidED25519Key` | `paseto.configuration.invalid_ed25519_key` | The Ed25519 PASETO key is invalid. |
| `JamPASETOInvalidSecp384r1Key` | `paseto.configuration.invalid_secp384r1_key` | The SECP384R1 PASETO key is invalid. |
| `JamPASETOInvalidPurpose` | `paseto.configuration.invalid_purpose` | The PASETO purpose is invalid. |
| `JamPASETOInvalidTokenFormat` | `paseto.validation.invalid_token_format` | The token has an invalid PASETO format. |
| `JamPASETOKeyVerificationError` | `paseto.key_verification_failed` | PASETO key verification failed. |

`JamPASETOInvalidTokenFormat` may provide a more specific validation code:

| Code | Description |
| --- | --- |
| `paseto.validation.invalid_authentication_tag` | The authentication tag is invalid. |
| `paseto.validation.invalid_body` | The token body is invalid. |
| `paseto.validation.invalid_header` | The PASETO header is invalid. |
| `paseto.validation.invalid_payload_signature_size` | The combined payload and signature size is invalid. |
| `paseto.validation.invalid_payload_size` | The payload size is invalid. |

## Framework plugins

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamLitestarPluginConfigError` | `jam.configuration.plugin.litestar` | The Litestar plugin is configured incorrectly. |
| `JamLitestarPluginError` | `jam.plugin.litestar` | A Litestar plugin operation failed. |
| `JamFlaskPluginConfigError` | `jam.configuration.plugin.flask` | The Flask plugin is configured incorrectly. |
| `JamFlaskPluginError` | `jam.plugin.flask` | A Flask plugin operation failed. |
| `JamStarlettePluginConfigError` | `jam.configuration.plugin.starlette` | The Starlette plugin is configured incorrectly. |
| `JamStarlettePluginError` | `jam.plugin.starlette` | A Starlette plugin operation failed. |

## SAML

These exceptions are defined in `jam.exceptions.saml`; commonly used classes
are also exported from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamSAMLError` | `saml.error` | A SAML operation failed. |
| `JamSAMLExpired` | `saml.assertion_expired` | The SAML assertion has expired. |
| `JamSAMLNotYetValid` | `saml.assertion_not_yet_valid` | The SAML assertion is not valid yet. |
| `JamSAMLInvalidAudience` | `saml.invalid_audience` | Assertion audience validation failed. |
| `JamSAMLInvalidIssuer` | `saml.invalid_issuer` | Assertion issuer validation failed. |
| `JamSAMLEmptyPrivateKey` | `saml.config.empty_private_key` | A private key required for SAML signing is missing. |
| `JamSAMLEmptyPublicKey` | `saml.config.empty_public_key` | A public key required for SAML verification is missing. |
| `JamSAMLUnsupportedAlgorithm` | `saml.config.unsupported_algorithm` | The configured SAML algorithm is unsupported. |
| `JamSAMLValidationError` | `saml.validation.assertion_error` | SAML assertion validation failed. |
| `JamSAMLInvalidRecipient` | `saml.invalid_recipient` | The assertion recipient does not match the expected ACS URL. |
| `JamSAMLReplayDetected` | `saml.replay_detected` | A previously consumed SAML message ID was reused. |
| `JamSAMLSOAPError` | `saml.soap_error` | SAML SOAP or artifact resolution failed. |

## Sessions

Import these exceptions from `jam.exceptions`.

| Exception | Default code | Description |
| --- | --- | --- |
| `JamSessionNotFound` | `sessions.not_found` | The requested session does not exist. |
| `JamSessionEmptyAESKey` | `sessions.empty_aes_key` | The AES key required for session encryption is empty. |

## Context-specific error codes

Some operations raise `JamError`, `JamValidationError`, or
`JamConfigurationError` with a code that is more specific than the class
default. Use this index when the code from a caught exception does not appear
in the class tables above.

### General

| Code | Exception | Description |
| --- | --- | --- |
| `jam.cli` | `JamError` | The optional dependencies required by the Jam CLI are not installed. |
| `plugins.disable` | `JamConfigurationError` | Experimental plugins are disabled. |

### Configuration loading

| Code | Exception | Description |
| --- | --- | --- |
| `config.validation_error` | `JamConfigurationError` | Configuration schema validation failed. |
| `configuration.env_var_not_set` | `JamConfigurationError` | A referenced environment variable is not set and has no default. |
| `configuration.env_vat_not_set` | `JamConfigurationError` | A referenced environment variable is not set. |
| `configuration.file_not_found` | `JamConfigurationError` | The requested YAML, TOML, or JSON configuration file does not exist. |
| `configuration.import_error` | `JamConfigurationError` | PyYAML is required to read or generate YAML configuration. |
| `configuration.invalid_config_type` | `JamConfigurationError` | The configuration file type is not YAML, TOML, or JSON. |
| `configuration.json_parse_error` | `JamConfigurationError` | JSON configuration parsing failed. |
| `configuration.toml_error` | `JamConfigurationError` | TOML configuration parsing failed. |
| `configuration.toml_not_installed` | `JamConfigurationError` | TOML support is not available in the current environment. |
| `configuration.yaml_error` | `JamConfigurationError` | YAML configuration parsing failed. |

### Module configuration

| Code | Exception | Description |
| --- | --- | --- |
| `configuration.authenticate_unknown_via` | `JamConfigurationError` | `authenticate()` received an unknown authentication mechanism. |
| `configuration.issue_unknown_via` | `JamConfigurationError` | `issue()` received an unknown credential mechanism. |
| `configuration.authz.invalid_permissions` | `JamConfigurationError` | Authorization permissions are not a list of non-empty strings. |
| `configuration.authz.invalid_rule` | `JamConfigurationError` | An authorization rule is invalid. |
| `configuration.jwe.not_configured` | `JamConfigurationError` | The JWE module is not configured. |
| `configuration.keychain.missing_path` | `JamConfigurationError` | A file-backed KeyChain has no storage path. |
| `configuration.keychain.not_configured` | `JamConfigurationError` | The requested KeyChain is not configured. |
| `configuration.keychain.unknown_type` | `JamConfigurationError` | The configured KeyChain type is unknown. |
| `configuration.lists.unknown_backend` | `JamConfigurationError` | The configured token-list backend is unknown. |
| `configuration.lists.unknown_type` | `JamConfigurationError` | The configured async token-list type is unknown. |
| `configuration.macaroon.invalid_keychain` | `JamConfigurationError` | The KeyChain algorithm is incompatible with macaroons. |
| `configuration.macaroon.invalid_location` | `JamConfigurationError` | The macaroon location is not a valid string. |
| `configuration.macaroon.missing_keychain` | `JamConfigurationError` | Macaroon profile operations require a KeyChain. |
| `configuration.macaroon.not_configured` | `JamConfigurationError` | The macaroon module is not configured. |
| `configuration.otp.unknown_type` | `JamConfigurationError` | The configured OTP type is unknown. |
| `configuration.paseto.not_configured` | `JamConfigurationError` | The PASETO module is not configured. |
| `configuration.paseto.unknown_list_type` | `JamConfigurationError` | The configured PASETO token-list type is invalid. |
| `configuration.paseto.unknown_version` | `JamConfigurationError` | The configured PASETO version is unknown. |
| `configuration.saml.invalid_module` | `JamConfigurationError` | The configured SAML module does not implement `BaseSAML`. |
| `configuration.saml.missing_audience` | `JamConfigurationError` | SAML issuance has no audience. |
| `configuration.saml.missing_issuer` | `JamConfigurationError` | SAML issuance has no issuer. |
| `configuration.saml.missing_subject` | `JamConfigurationError` | SAML issuance has no subject ID. |
| `configuration.saml.not_configured` | `JamConfigurationError` | The SAML module is not configured. |
| `configuration.session.not_configured` | `JamConfigurationError` | The session module is not configured. |
| `configuration.session.unknown_type` | `JamConfigurationError` | The configured session type is unknown. |
| `macaroon.configuration` | `JamConfigurationError` | The macaroon configuration is invalid. |

### JWT configuration

| Code | Exception | Description |
| --- | --- | --- |
| `configuration.jwt.conflicting_jwe` | `JamConfigurationError` | Both `enc` and `jwe` were supplied. |
| `configuration.jwt.conflicting_jws` | `JamConfigurationError` | Both `alg` and `jws` were supplied. |
| `configuration.jwt.jwe_not_configured` | `JamConfigurationError` | A JWT encryption operation was requested without JWE configuration. |
| `configuration.jwt.jws_not_configured` | `JamConfigurationError` | A JWT signing operation was requested without JWS configuration. |
| `configuration.jwt.missing_enc` | `JamConfigurationError` | JWT encryption has no content-encryption algorithm. |
| `configuration.jwt.missing_jws_key` | `JamConfigurationError` | JWT signing has no algorithm or key. |
| `configuration.jwt.no_algorithm` | `JamConfigurationError` | No JWT signing or encryption algorithm was supplied. |
| `configuration.jwt.not_configured` | `JamConfigurationError` | The JWT module is not configured. |
| `configuration.jwt.unknown_list_type` | `JamConfigurationError` | The configured JWT token-list type is invalid. |

### PASETO configuration and validation

| Code | Exception | Description |
| --- | --- | --- |
| `paseto.config.v2_key_format_error` | `JamPASETOInvalidED25519Key` | A v2.public secret key is not an Ed25519 private key. |
