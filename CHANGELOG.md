# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- 
## VERSION - [unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security
-->

## 4.0.0 - [unreleased]

### Added
- `ConfigMeta` metaclass (`jam.utils.config_meta`) — classes accept `config` /
  `pointer` kwargs; config values are injected into `__init__` parameters by
  signature, explicit kwargs always win
- `jam.lists` module with `BaseList`, `MemoryList`, `RedisList`, `JSONList`
  and the `build_list(config)` factory
- `jam.subject.BaseSubject` — dataclass contract for auth subjects (mandatory
  `id` field) with generic `to_dict()` / `from_dict()` serialization
- `jam.authz` — `BasePolicy` interface and declarative `Policy` built from
  `{permission: [predicates]}` rules (`"*"` wildcard, `field=value`, `field`),
  deny by default
- Config-driven module init: JWT/JWS/JWE, PASETO (`v1`-`v4`), sessions
  (`redis`/`json`), OAuth2 providers and authz are built directly from
  `[jam]` config sections
- New `Jam` facade API:
  - `issue(subject, via=None, exp/iss/aud/nbf/jti, **claims)` — issues a
    JWT, PASETO or session (auto-detects when `via=None`)
  - `authenticate(token, via=None)` — verifies a token/session and returns a
    `BaseSubject` (or raw payload dict)
  - `authorize(subject, permission)` — checks the `[jam.authz]` policy
  - `subject` / `config` as class attributes overridable via `__init__`
- `jam.utils.redaction.SensitiveDataFilter` — attached to the `"jam"`
  logger by default; redacts JWT/JWE/PASETO tokens, PEM private keys and
  `key=value` secrets from log records (disable with `JAM_DEBUG=True`)
- `NullHandler` added to the `"jam"` logger so Jam emits no log output
  unless the application configures logging

### Changed
- JWT: `__init__` accepts `config` / `pointer`; `list` parameter accepts
  `dict | BaseList | None`; `decode()` gained `check_list: bool = True`
- JWS/JWE: `config` / `pointer` kwargs added
- PASETO: `BasePASETO.__init__(purpose, secret_key, list, config,
  pointer)`; `.key()` kept as an alias; white/black list handling moved into
  the base (`_list_add` / `_list_check`)
- Sessions: `BaseSessionModule` uses `ConfigMeta` with `_SESSION_TYPE`
  validation (`sessions_type` kept as a deprecated alias)
- OAuth2: `create_instance` replaced by `build_clients(providers, serializer)`
- The module config schema moved from `[jam.jwt]` to `[jam.jose.jwt]`
- PASETO v1–v4 refactored onto shared mixins in `jam.paseto.__base__`
  (`LegacyAEADMixin`, `XChaChaMixin`, `KeyLoadMixin`); local encode/decode and
  footer parsing are now defined once
- `JamConfigurationError` raises in JWT/PASETO carry machine-readable
  `error_code` values (`configuration.jwt.*`, `configuration.paseto.*`)
- Logging calls in hot paths (sign/verify/wrap/unwrap, sessions, lists) use
  lazy `%s` formatting on module-level `logging.getLogger(__name__)` loggers
- `BaseJam.__init__` uses `None` defaults for `config` / `plugins` instead of
  mutable class attributes
- `BaseSubject.from_dict` ignores unknown keys; `id` is a plain field
  annotation; dead `__abstract_methods__` marker removed
- `authz.Policy._match` compares `field=value` predicates literal-aware
  (via `ast.literal_eval`) with a string fallback
- `Jam.issue(via="paseto")` now forwards `nbf` to the PASETO payload
- `JamPASTOKeyVerificationError` (typo) renamed to
  `JamPASETOKeyVerificationError`; `JamPASETOInvalidPurpose` now inherits from
  `JamConfigurationError`

### Deprecated
- `sessions_type` parameter in session modules (use `session_type`)

### Removed
- `jam.logger` module with `BaseLogger` / `JamLogger` — all modules now use
  the standard `logging` library with `logging.getLogger(__name__)` loggers
- `logger` / `log_level` kwargs from `Jam`, `BaseJam`, `JWT`, `JWS`, `JWE`,
  PASETO, session modules and lists; logging is configured through the
  standard `logging` API instead
- `build_list(config, logger)` — the `logger` argument is gone
- `jam.jose.create_jwt_instance` / `create_jws_instance` / `create_jwe_instance`
  / `create_instance` factories — construct `JWT` / `JWS` / `JWE` directly
- Deprecated `jam.jwt` module and the `[jam.jwt]` → `[jam.jose.jwt]` config
  migration
- All deprecated `Jam` wrapper methods: `jwt_make_payload`, `jwt_create`,
  `jwt_encode`, `jwt_decode`, `jws_sign`, `jws_verify`, `jwe_encrypt`,
  `jwe_decrypt`, `session_*`, `otp_*`, `oauth2_*`, `paseto_make_payload`,
  `paseto_create`, `paseto_decode` — use the module attributes and the new
  `issue` / `authenticate` / `authorize` API
- `BaseJam` old abstract interface and the `MODULES` factory map
- Dead code: `jam.utils.version_check`, the `jam.jose.lists` package alias,
  `MsgspecJsonEncoder`, `paseto.utils.__b64url_nopad__`, and the never-raised
  exceptions `JamJWTEmptySecretKey`, `JamJWTEmptyPrivateKey`,
  `JamJWTValidationError`, `JamJWKMissingParameterError`

### Fixed
- PASETO v1: dead length check on the local key no longer shadows key loading
- JWT `_detect_key_type` tries PEM/DER public key loaders before falling back
  to symmetric, so JWE with a public key is handled correctly
- `Jam.authenticate` / token auto-detection now routes JWE tokens (4 segments)
  to `jwt.decrypt` instead of failing as a session
- JWS/JWE/JWT `encode` / `decode` raise `JamConfigurationError` with
  `error_code` when the module is not configured instead of a bare assert

### Security

---

## [3.3.0] - 01.08.2026

### Added
- Complete SAML 2.0 module (`jam.saml`):
  - Both roles: Service Provider (SP) and Identity Provider (IdP)
  - Bindings: HTTP-POST, HTTP-Redirect, HTTP-Artifact + SOAP back-channel
  - XML-DSig signatures (RSA-SHA256) with embedded certificates
  - Assertion encryption (AES-256-GCM + RSA-OAEP) via `EncryptedAssertion`
    with automatic decryption on the SP side
  - Single Logout (SLO)
  - Attribute Query
  - NameID Management
  - Metadata generation and parsing
  - Replay protection and clock skew tolerance
  - XXE-safe XML parsing
  - `create_instance` factory
  - 12 dedicated `JamSAML*` exceptions

### Fixed
- SAML: `resolve_artifact()` now raises `JamSAMLSOAPError` on malformed SOAP
  responses instead of `JamSAMLValidationError`
- SAML: `encrypt_aes_key()` no longer returns a dead second tuple element
- SAML: `parse_metadata()` return type annotation is now `SAMLMetadata`
- SAML: None-safe text extraction in request/response parsers
- JWE: RSA/EC private key objects (not just PEM) now work for decryption
- JOSE: key algorithms no longer crash when loading private key objects
- Redis list: `check_many()` now returns correct per-token results instead of
  iterating the integer `EXISTS` return value
- Litestar: PASETO middleware decodes `(payload, footer)` correctly and passes
  the token model as `auth` to `AuthenticationResult`

---

## [3.2.0] - 19.05.2026

### Added
- Complete JOSE module (`jam.jose`):
  - `JWS` - JSON Web Signature (RFC 7515)
  - `JWE` - JSON Web Encryption (RFC 7516)
  - `JWK` / `JWKSet` - JSON Web Key (RFC 7517)
  - `JWT` - JSON Web Token (RFC 7519)
- JWT token lists (black/white) with pluggable backends: Redis, JSON, in-memory
- Factory functions: `create_jwt_instance`, `create_jws_instance`,
  `create_jwe_instance`
- `JamJWTNotYetValid` exception for nbf claim validation
- `check_nbf` parameter in `Jam.jwt_decode()` and `Jam.aio.jwt_decode()`
- `include_headers` parameter in `Jam.jwt_decode()` and `Jam.aio.jwt_decode()`
- `jti` parameter in `Jam.jwt_encode()` and `Jam.aio.jwt_encode()`
- Pre-built JWS/JWE instances support in JWT constructor
- Critical header (`crit`) validation per RFC 7515
- HKDF key derivation for symmetric sign-then-encrypt

### Changed
- JWT sign-then-encrypt now follows RFC 7519 nested JWT specification
- JWE key management algorithm auto-detected based on key type:
  RSA → `RSA-OAEP`, EC → `ECDH-ES`, symmetric → `A256KW` / `A128KW`
- `exp` and `nbf` claims validation moved from JOSE module to `Jam` instances
- `JWT.decode()` consistently returns `{"header": dict, "payload": dict}`
- Updated TestClients

### Deprecated
- `jam.Jam.jwt_make_payload`: Use JWS for signing
- `jam.Jam.jwt_create`: Use `jam.Jam.jwt_encode`
- `jam.jwt.JWT`: Use `jam.jose.JWT`

### Removed
- `JsonEncoder` and `BaseEncoder` from `__all__` exports

### Fixed
- Typo in CLI documentation (`bahs` → `bash`)

### Security
- Algorithm `none` explicitly disabled

---

## [3.1.2] - 06-05-2026

### Security
- Update cryptography to 48.0.0

---

## [3.1.1] - 05-05-2026

### Added
- Experemental plugin system.
- AGENTS.md file.

### Changed
- Remove `unstable` branch.

### Fixed
- Fix typo in main instance.

---

## [3.1.0] - 16-03-2026

### Added
- Add CLI tool for generate keys.

---

## [3.0.0] - 15-03-2026

### Added
- New changelog format.
- JSON configuration.
- New JWT module.
- Environment variable support in config.
- PASETO v1–v4 modules.
- New utilities:
  - Utility for generating symmetric keys
  - Utility for generating ED key pairs
- Added the ability to specify server keys as a path to a file. 

### Changed
- License changed to Apache-2.0.
- Renamed all `__abc_*_module__` to `__base__`.
- Exception format updated.
- Refactored Litestar plugins.
- Refactored Flask extensions.
- Refactored Starlette integrations.
- Renamed `default_ttl` to `ttl` in Redis sessions.

### Removed
- Removed obsolete dependencies.
- Removed module `jam.modules`.
- Removed all deprecated modules.

### Fixed
- YAML config builder.
- Fixed JWT lists in Starlette/FastAPI extensions.
- Fixed all typo errors.

### Security
- Updated all dependencies.

---

- [3.3.0] https://github.com/lyaguxafrog/jam/compare/v3.2.0...v3.3.0
- [3.2.0] https://github.com/lyaguxafrog/jam/compare/v3.1.2...v3.2.0
- [3.1.2] https://github.com/lyaguxafrog/jam/compare/v3.1.1...v3.1.2
- [3.1.1] https://github.com/lyaguxafrog/jam/compare/v3.1.0...v3.1.1
- [3.1.0] https://github.com/lyaguxafrog/jam/compare/v3.0.0...v3.1.0
- [3.0.0] https://github.com/lyaguxafrog/jam/compare/v2.5.6...v3.0.0
