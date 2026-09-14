---
title: Algorithms
---

## Overview

JOSE supports multiple algorithms organized into three categories:

- **Signing Algorithms** (JWS) - for creating and verifying digital signatures
- **Key Management Algorithms** (JWE) - for encrypting Content Encryption Keys
- **Content Encryption Algorithms** (JWE) - for encrypting payload data

## Signing Algorithms (JWS)

Used with `JWS` class and `JWT.encode()` / `JWT.decode()`.

### HMAC (Symmetric)

| Algorithm | Key Size | Notes |
|-----------|----------|-------|
| `HS256` | 256-bit | HMAC with SHA-256 |
| `HS384` | 384-bit | HMAC with SHA-384 |
| `HS512` | 512-bit | HMAC with SHA-512 |

Requires a shared secret key on both sides.

```python
from jam.jose import JWS, JWT

# JWS
jws = JWS(alg="HS256", key="shared-secret-key-32-bytes!")
token = jws.sign(header={}, data={"data": "value"})

# JWT
jwt = JWT(alg="HS256", secret_key="shared-secret-key-32-bytes!")
token = jwt.encode(exp=3600, payload={"user": "admin"})
```

### RSA (Asymmetric)

| Algorithm | Signature Type | Notes |
|-----------|----------------|-------|
| `RS256` | PKCS#1 v1.5 | SHA-256 |
| `RS384` | PKCS#1 v1.5 | SHA-384 |
| `RS512` | PKCS#1 v1.5 | SHA-512 |

Uses RSA key pair. Sign with private key, verify with public key.

```python
from jam.jose import JWS, JWT

# Sign with private key
jws_sign = JWS(alg="RS256", key=rsa_private_key)
token = jws_sign.sign(header={}, data={"data": "value"})

# Verify with public key
jws_verify = JWS(alg="RS256", key=rsa_public_key)
result = jws_verify.verify(token)

# JWT
jwt = JWT(alg="RS256", secret_key=rsa_private_key)
token = jwt.encode(exp=3600, payload={"user": "admin"})
```

### ECDSA (Asymmetric)

| Algorithm | Curve | Notes |
|-----------|-------|-------|
| `ES256` | P-256 | 256-bit security |
| `ES384` | P-384 | 384-bit security |
| `ES512` | P-521 | 521-bit security |

Shorter signatures compared to RSA.

```python
from jam.jose import JWS, JWT

jws = JWS(alg="ES256", key=ec_private_key)
token = jws.sign(header={}, data={"data": "value"})

jwt = JWT(alg="ES256", secret_key=ec_private_key)
token = jwt.encode(exp=3600, payload={"user": "admin"})
```

### RSA-PSS (Asymmetric)

| Algorithm | Signature Type | Notes |
|-----------|----------------|-------|
| `PS256` | PSS | SHA-256, probabilistic |
| `PS384` | PSS | SHA-384, probabilistic |
| `PS512` | PSS | SHA-512, probabilistic |

More modern RSA signature scheme with probabilistic salt.

```python
from jam.jose import JWS, JWT

jws = JWS(alg="PS256", key=rsa_private_key)
token = jws.sign(header={}, data={"data": "value"})

jwt = JWT(alg="PS256", secret_key=rsa_private_key)
token = jwt.encode(exp=3600, payload={"user": "admin"})
```

---

## Key Management Algorithms (JWE)

Used with `JWE` class for encrypting Content Encryption Keys.

### RSA

| Algorithm | Type | Notes |
|-----------|------|-------|
| `RSA1_5` | RSA | PKCS#1 v1.5 (legacy, not recommended) |
| `RSA-OAEP` | RSA | OAEP with SHA-256 (recommended) |
| `RSA-OAEP-256` | RSA | OAEP with SHA-256 (same as RSA-OAEP) |

Encrypt CEK with RSA public key, decrypt with private key.

```python
from jam.jose import JWE

jwe = JWE(
    alg="RSA-OAEP",
    enc="A128CBC-HS256",
    key=rsa_public_key
)
token = jwe.encrypt(plaintext={"data": "sensitive"})

jwe_dec = JWE(
    alg="RSA-OAEP",
    enc="A128CBC-HS256",
    key=rsa_private_key
)
data = jwe_dec.decrypt(token)
```

### AES Key Wrap

| Algorithm | Key Size | Notes |
|-----------|---------|-------|
| `A128KW` | 128-bit | AES Key Wrap |
| `A192KW` | 192-bit | AES Key Wrap |
| `A256KW` | 256-bit | AES Key Wrap |

Symmetric key wrapping. Requires shared key.

```python
from jam.jose import JWE

jwe = JWE(
    alg="A256KW",
    enc="A256GCM",
    key="your-256-bit-key-here!!"  # 32 bytes
)
token = jwe.encrypt(plaintext="secret")
```

### ECDH-ES

| Algorithm | Curve | Notes |
|-----------|-------|-------|
| `ECDH-ES` | - | Ephemeral-static ECDH, CEK = derived key |
| `ECDH-ES+A128KW` | P-256 | ECDH with AES key wrap |
| `ECDH-ES+A192KW` | P-384 | ECDH with AES key wrap |
| `ECDH-ES+A256KW` | P-521 | ECDH with AES key wrap |

Ephemeral-static ECDH provides perfect forward secrecy.

```python
from jam.jose import JWE

jwe = JWE(
    alg="ECDH-ES+A256KW",
    enc="A128CBC-HS256",
    key=ec_public_key
)
token = jwe.encrypt(plaintext={"data": "sensitive"})
```

### AES-GCM Key Wrap

| Algorithm | Key Size | Notes |
|-----------|----------|-------|
| `A128GCMKW` | 128-bit | AES-GCM key wrap |
| `A256GCMKW` | 256-bit | AES-GCM key wrap |

Similar to AES Key Wrap but uses GCM mode.

```python
from jam.jose import JWE

jwe = JWE(
    alg="A256GCMKW",
    enc="A256GCM",
    key="your-256-bit-key-here!!"
)
token = jwe.encrypt(plaintext={"data": "sensitive"})
```

### PBES2 (Password-Based)

| Algorithm | Hash | Key Wrap | Notes |
|-----------|------|----------|-------|
| `PBES2-HS256+A128KW` | SHA-256 | A128KW | 100k iterations |
| `PBES2-HS384+A192KW` | SHA-384 | A192KW | 100k iterations |
| `PBES2-HS512+A256KW` | SHA-512 | A256KW | 100k iterations |

Password-based encryption using PBKDF2 with AES key wrap.

```python
from jam.jose import JWE

jwe = JWE(
    alg="PBES2-HS512+A256KW",
    enc="A256CBC-HS512",
    password=b"user_password"
)
token = jwe.encrypt(plaintext={"data": "sensitive"})
```

---

## Content Encryption Algorithms (JWE)

Used with `JWE` class for encrypting payload data.

### AES-CBC-HS

| Algorithm | Key Size | MAC Size | Notes |
|-----------|----------|----------|-------|
| `A128CBC-HS256` | 256-bit | 128-bit | HMAC-SHA-256 |
| `A192CBC-HS384` | 384-bit | 192-bit | HMAC-SHA-384 |
| `A256CBC-HS512` | 512-bit | 256-bit | HMAC-SHA-512 |

HMAC-based authenticated encryption in CBC mode.

```python
from jam.jose import JWE

jwe = JWE(
    alg="RSA-OAEP",
    enc="A128CBC-HS256",
    key=rsa_public_key
)
token = jwe.encrypt(plaintext={"data": "sensitive"})
```

### AES-GCM

| Algorithm | Key Size | Notes |
|-----------|----------|-------|
| `A128GCM` | 128-bit | Authenticated encryption |
| `A256GCM` | 256-bit | Authenticated encryption |

Galois/Counter Mode provides built-in authenticated encryption.

```python
from jam.jose import JWE

jwe = JWE(
    alg="A256KW",
    enc="A256GCM",
    key="your-256-bit-key-here!!"
)
token = jwe.encrypt(plaintext={"data": "sensitive"})
```

---

## Algorithm Combinations

Common recommended combinations:

### Symmetric (HMAC)

```
HS256 + A128CBC-HS256  → Basic security
HS384 + A192CBC-HS384  → Medium security
HS512 + A256CBC-HS512  → High security
```

### RSA (Asymmetric)

```
RS256/PS256 + RSA-OAEP + A128CBC-HS256  → Basic RSA encryption
RS512/PS512 + RSA-OAEP + A256CBC-HS512  → High security RSA encryption
```

### ECDH (Perfect Forward Secrecy)

```
ES256 + ECDH-ES + A128CBC-HS256   → P-256 ECDH
ES384 + ECDH-ES+A192KW + A192CBC-HS384  → P-384 ECDH
ES512 + ECDH-ES+A256KW + A256CBC-HS512  → P-521 ECDH
```

---

## Algorithm Security Notes

| Algorithm | Status | Notes |
|-----------|--------|-------|
| `RSA1_5` | ⚠️ Legacy | PKCS#1 v1.5 has known vulnerabilities, avoid if possible |
| `none` | ❌ Disabled | Algorithm "none" is not supported for security |
| `HS256` | ✓ | Secure with sufficient key length (256+ bits) |
| `RS256` | ✓ | Secure with sufficient key size (2048+ bits) |
| `ES256` | ✓ | Recommended for new implementations |
| `RSA-OAEP` | ✓ | Recommended, uses SHA-256 |
| `A128GCM` | ✓ | Authenticated encryption |
| `PBES2-*` | ✓ | Secure with strong passwords |