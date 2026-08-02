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

### Changed

### Deprecated

### Removed

### Fixed

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

- [3.2.0] https://github.com/mkrdnk/jam/compare/v3.1.2...v3.2.0
- [3.1.2] https://github.com/mkrdnk/jam/compare/v3.1.1...v3.1.2
- [3.1.1] https://github.com/mkrdnk/jam/compare/v3.1.0...v3.1.1
- [3.1.0] https://github.com/mkrdnk/jam/compare/v3.0.0...v3.1.0
- [3.0.0] https://github.com/mkrdnk/jam/compare/v2.5.6...v3.0.0
