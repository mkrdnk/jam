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

## 4.2.0 - 2026-09-21

### Added

- Added first-class Macaroon credentials with explicit synchronous and
  asynchronous `Jam.issue(..., via="macaroon")` and
  `Jam.authenticate(..., via="macaroon")` flows.
- Added a standalone `jam.macaroons` module with standard binary v2
  serialization, immutable attenuation, opaque and structured first-party
  caveats, third-party caveats, bound and nested discharge Macaroons, and
  compatibility with reference implementations.
- Added built-in `permission`, `condition`, `expires_at`, and `not_before`
  caveats, plus an instance-owned `CaveatRegistry` for custom structured
  caveats.
- Added generic `AuthorizationConstraint`, `ConditionConstraint`, and
  `PermissionConstraint` types. Authenticated principals now carry immutable
  credential constraints separately from root claims and permissions.
- Added `MACAROON-HMAC-SHA256` KeyChain support, including historical-key
  verification, rotation, revocation, `Memory`, and `FileStorage`.
- Added Macaroon support to the Django credential adapters and documentation
  for configuration, attenuation, custom and opaque caveats, and discharge
  acquisition.
- Added first-class SAML credentials to the synchronous and asynchronous
  facades through `Jam.issue(..., via="saml")` and
  `Jam.authenticate(..., via="saml")`. Facade authentication returns a
  `Principal` containing the verified assertion subject, attributes, and
  registered claims.
- Added config-driven `SAML` construction and `[jam.saml]` facade assembly,
  including issuer and audience defaults, expected-issuer validation, custom
  modules, and direct `config` / `pointer` construction.
- Added SAML KeyChain signing and verification with XML `KeyInfo/KeyName`,
  historical-key lookup, rotation, revocation, `Memory`, and `FileStorage`
  support.

### Changed

- Authorization internals now live in the `jam.authz` package with separate
  contracts, constraints, policy compilation, roots, and condition helpers.
  Existing `from jam.authz import ...` imports remain supported.
- Credential constraints are evaluated before the configured authorization
  policy. They can only reduce authority; a custom policy cannot bypass a
  failing constraint or widen a Macaroon's root permissions.
- Optional authentication modules are imported only when configured, allowing
  a Macaroon-only Jam instance to run without unrelated extras.
- Macaroon verification now accepts serialized primary and discharge tokens
  only. The decoded `Macaroon` model remains available for attenuation and must
  be serialized again before verification.
- SAML response issuance now supports per-credential lifetime, not-before, and
  assertion ID values through the facade's `exp`, `nbf`, and `jti` arguments.

### Removed

- Removed the unused internal version compatibility helper and the direct
  `packaging` dependency. `cryptography` is now Jam's only mandatory runtime
  dependency.
- [Remove CLAUDE.md](https://code.claude.com/docs/en/changelog#2-1-277) file.

### Fixed

- Missing context data, references, malformed condition values, unsafe regular
  expressions, unsupported caveats, invalid timestamps, and runtime comparison
  mismatches now fail closed for credential constraints.
- Django principal adaptation now preserves credential constraints.
- Macaroon time boundaries now fail during authentication and remain mandatory
  authorization constraints. Configurable issuer, audience, and floating-point
  clock leeway checks are available in the Macaroon profile.
- SAML public-key loading now accepts RSA private PEM material and derives its
  public key, allowing generated `FileStorage` KeyChains to verify assertions.

### Security

- Macaroon signatures and complete discharge graphs are verified before
  structured caveats or application satisfiers are invoked.
- Added strict canonical parsing and configurable limits for serialized size,
  caveat payloads, total caveat count, discharge count, and discharge depth.
- SAML facade authentication fails closed for unsuccessful responses, missing
  subject assertions, invalid signatures, issuer or audience mismatches,
  expired or not-yet-valid assertions, replayed message IDs, and revoked keys.
- Structured Macaroon satisfiers receive deeply immutable JSON values, so
  callbacks cannot change the signed caveat represented by verification
  results.
- Added an internal NaCl-compatible XSalsa20-Poly1305 SecretBox implementation
  for third-party caveat keys without an additional runtime dependency.
  Poly1305 tags are verified before plaintext is returned. The Salsa20
  implementation is pure Python and is not suitable when local or
  high-resolution timing attackers are in scope.

---

## [4.1.3] - 2026-09-18

### Added
- Added `aauthorize()` for non-blocking permission checks in asynchronous
  Django Modern REST controllers.
- Added `source="session"` as an explicit session-only mode for
  `JamSyncAuth` and `JamAsyncAuth`.

### Changed
- DMR authorization helpers now preserve an existing resource when `resource`
  is omitted and allow it to be cleared explicitly with `resource=None`.
- DMR OpenAPI output now rejects auth instances with no enabled mechanism and
  documents custom session-header prefixes and cookie-session CSRF responses.
- Updated the 4.1.3 documentation and README links for the current
  documentation layout, including valid serializer-backed DMR controllers.

### Fixed
- Fixed DMR examples that used serializer-free controllers for Python return
  values or imported decorators from an unsupported module.
- Clarified Bearer-or-Session configuration so OpenAPI describes alternative
  authentication methods instead of requiring both.

### Security
- Jam Session credentials read from cookies now enforce Django CSRF validation
  for unsafe requests in synchronous and asynchronous DMR controllers.

---

## [4.1.2] - 2026-09-18

### Fixed
- Fix documentation routing.

---

## [4.1.1] - 2026-09-18

### Fixed
- Build workflows
- Linter workflows

---

## [4.1.0] - 2026-09-18

### Added
- Integration with django `jam.ext.django`:
  - Django-native auth perms
  - Mixins
  - Templates permissions
  - Django REST framework (`drf`) integration
  - Django modern REST (`dmr`) integration
- Added more logs hooks.

### Fixed
- Fix keychain docs

---

## [4.0.0] - 2026-09-16

### Added
- `ConfigMeta` metaclass (`jam.utils.config_meta`) — classes accept `config` /
  `pointer` kwargs; config values are injected into `__init__` parameters by
  signature, explicit kwargs always win
- `jam.lists` module with `BaseList`, `MemoryList`, `RedisList`, `JSONList`
  and the `build_list(config)` factory
- `jam.subject.BaseSubject` — dataclass contract for auth subjects (mandatory
  `id` field) with generic `to_dict()` / `from_dict()` serialization
- `jam.authz` — `BasePolicy` interface and declarative `Policy` built from
  compact predicates or structured allow/deny rules; supports credential
  permissions, permission wildcards, dynamic authorization context,
  `all` / `any` / `not` conditions and deny-by-default evaluation
- `Principal` authentication result preserves the typed subject and verified
  credential claims; `AuthorizationContext` supplies the current time,
  resource, request and application attributes to authorization policies
- Config-driven module init: JWT/JWS/JWE, PASETO (`v1`-`v4`), sessions
  (`redis`/`json`), OAuth2 providers and authz are built directly from
  `[jam]` config sections
- New `Jam` facade API:
  - `issue(subject, via, exp/iss/aud/nbf/jti, permissions, **claims)` —
    issues a JWT, PASETO or session with per-credential permission grants;
    `via` is one of `"jwt"`, `"paseto"` or `"session"`
  - `authenticate(token, via)` — verifies a JWT, JWE, PASETO or session and
    returns a `Principal`; `via` is required
  - `authorize(principal, permission, context=None)` — checks credential
    grants and the `[jam.authz]` policy
  - `subject` / `config` as class attributes overridable via `__init__`
- Independent `jam.aio.AsyncJam` facade with awaitable `issue()` and
  `authenticate()`, native async Redis sessions/token lists and async OAuth2
  HTTP; `jam.aio.Jam` remains an import-compatible alias
- Async context management closes Redis and OAuth2 clients created by
  `AsyncJam`
- Config caching — config files are parsed once and cached per
  path + pointer (`JAM_CONFIG_CACHING=true`, default). Set
  `JAM_CONFIG_CACHING=false` to re-read config on every instance creation
  for runtime config updates. Manual invalidation via
  `jam.utils.config_maker.__config_cache_clear__`
- `jam.utils.redaction.SensitiveDataFilter` — attached to the `"jam"`
  logger by default; redacts JWT/JWE/PASETO tokens, PEM private keys and
  `key=value` secrets from log records (disable with `JAM_DEBUG=True`)
- `NullHandler` added to the `"jam"` logger so Jam emits no log output
  unless the application configures logging
- `authz.Policy` supports `@`-prefixed `value` references that resolve another
  field path (e.g. `subject.id == @context.resource.author_id`) for
  field-to-field comparisons
- `authz.Policy` field resolution supports arbitrary objects (pydantic models,
  ORM instances, plain classes) via public attributes, not just mappings and
  dataclasses; methods, callables and private attributes are never evaluated.
  Missing `field` values do not match; missing `@` references raise a
  configuration error (`exists` reports absence explicitly)
- Key rotation manager `jam.keychain`.

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
- Documentation refactoring. Migrate from mkdocs.

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
- Dead code: the `jam.jose.lists` package alias, `MsgspecJsonEncoder`,
  `paseto.utils.__b64url_nopad__`, and the never-raised exceptions
  `JamJWTEmptySecretKey`, `JamJWTEmptyPrivateKey`,
  `JamJWTValidationError`, `JamJWKMissingParameterError`

### Fixed
- KeyChain now generates the JOSE-mandated P-256, P-384 and P-521 curves for
  ES256, ES384 and ES512, and rejects keys whose curve does not match `alg`
- PASETO v1: dead length check on the local key no longer shadows key loading
- JWT `_detect_key_type` tries PEM/DER public key loaders before falling back
  to symmetric, so JWE with a public key is handled correctly
- `Jam.authenticate(via="jwe")` routes JWE tokens to `jwt.decrypt`
- JWS/JWE/JWT `encode` / `decode` raise `JamConfigurationError` with
  `error_code` when the module is not configured instead of a bare assert

### Security
- Update cryptography to 50.0.0

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

[4.2.0]: https://github.com/mkrdnk/jam/compare/v4.1.3...v4.2.0
[4.1.3]: https://github.com/mkrdnk/jam/compare/v4.1.2...v4.1.3
[4.1.2]: https://github.com/mkrdnk/jam/compare/v4.1.1...v4.1.2
[4.1.1]: https://github.com/mkrdnk/jam/compare/v4.1.0...v4.1.1
[4.1.0]: https://github.com/mkrdnk/jam/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/mkrdnk/jam/compare/v3.3.0...v4.0.0
[3.3.0]: https://github.com/mkrdnk/jam/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/mkrdnk/jam/compare/v3.1.2...v3.2.0
[3.1.2]: https://github.com/mkrdnk/jam/compare/v3.1.1...v3.1.2
[3.1.1]: https://github.com/mkrdnk/jam/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/mkrdnk/jam/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/mkrdnk/jam/compare/v2.5.6...v3.0.0
