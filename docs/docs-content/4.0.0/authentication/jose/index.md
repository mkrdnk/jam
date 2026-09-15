---
title: JOSE
---

## Overview

JOSE (JSON Object Signing and Encryption) is a set of standards for secure data transmission:

- **JWS** (RFC 7515) - JSON Web Signature - digital signature
- **JWE** (RFC 7516) - JSON Web Encryption - data encryption
- **JWK** (RFC 7517) - JSON Web Key - cryptographic key representation
- **RFC 7518** - JSON Web Algorithms - cryptographic algorithms
- **JWT** (RFC 7519) - JSON Web Token - compact token format

Jam provides a complete implementation of all JOSE standards with support for:

- Symmetric (HMAC) and asymmetric (RSA, ECDSA, RSA-PSS) signing algorithms
- Multiple key management algorithms (RSA, AES Key Wrap, ECDH-ES, PBES2,
  AES-GCM Key Wrap)
- Various content encryption modes (AES-CBC-HS, AES-GCM)
- Three token modes: JWS-only (signed), JWE-only (encrypted), JWS+JWE
  (sign-then-encrypt)
- Automatic JWE key management algorithm selection based on key type
- HKDF key derivation for symmetric sign-then-encrypt scenarios
- JWT standard claims validation (exp, nbf)
- Critical header (`crit`) validation per RFC 7515
- Token black/white lists with pluggable backends

## Exports

The `jam.jose` package exports the following:

**Classes:**

- `JWK` - JSON Web Key
- `JWKSet` - Set of JWK keys
- `JWKRSA`, `JWKEC`, `JWKOct` - TypedDicts for typed key definitions
- `JWS` - JSON Web Signature
- `JWE` - JSON Web Encryption
- `JWT` - JSON Web Token (supports all three token modes)

## Navigation

- [JWT](jwt.md) - high-level token operations
- [JWS](jws.md) - data signing and verification
- [JWE](jwe.md) - data encryption and decryption
- [JWK](jwk.md) - cryptographic keys management
- [Lists](lists.md) - token black and white lists
- [Algorithms](algorithms.md) - supported algorithms reference
