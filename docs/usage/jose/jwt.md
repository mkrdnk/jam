---
title: JWT
---

!!! tip
    The `jam.jwt` module is [deprecated](/breaking_changes/deprecated), but the
    documentation is still available at [/usage/jwt](/usage/jwt)

## Token modes

JWT supports three operating modes:

### JWS-only (signed tokens)

Standard signed JWT. Payload is readable by anyone but cannot be tampered with.

```python
jwt = JWT(alg="RS256", secret_key=private_key)
token = jwt.encode(sub="user", exp=3600)
data = jwt.decode(token)
```

### JWE-only (encrypted tokens)

Encrypted-only token. Payload is confidential but not integrity-protected by
signature.

```python
jwt = JWT(enc="A256GCM", secret_key=encryption_key)
token = jwt.encrypt({"secret": "data"})
data = jwt.decrypt(token)
```

### JWS+JWE (sign-then-encrypt, RFC 7519)

Hybrid mode: first signs the payload, then encrypts the signed token. Follows
RFC 7519 nested JWT pattern.

```python
jwt = JWT(alg="RS256", enc="A256GCM", secret_key=key)
token = jwt.encrypt({"data": "sensitive"})  # Signs then encrypts
data = jwt.decrypt(token)  # Decrypts then verifies signature
```

## Automatic JWE algorithm selection

When using JWS+JWE mode with a symmetric key, JWT automatically selects the JWE
key management algorithm based on key type:

| Key type | Auto-selected JWE `alg` |
|----------|------------------------|
| RSA | `RSA-OAEP` |
| EC | `ECDH-ES` |
| Symmetric (>=32 bytes) | `A256KW` |
| Symmetric (<32 bytes) | `A128KW` |

For symmetric keys, an encryption key is derived from the signing key using
HKDF-SHA256 with salt `jwe-encryption` and info `encryption-key`.

## Use in instance

### Config

```toml
[jam.jose.jwt]
alg = "RS256"
secret_key = "$RSA_PRIVATE_KEY"

[jam.jose.jwt.list]
type = "black"
backend = "redis"
redis_uri = "redis://localhost:6379"
```

Args:

* `alg`: `str` - JWT signing algorithm. Supports: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`.
* `enc`: `str | None` - Content encryption algorithm. Configures JWE mode (see [Token modes](#token-modes)).
* `secret_key`: `str` - Key for signing/encryption. Default reads from `JAM_JWT_SECRET_KEY` environment variable.
* `password`: `str | None` - Password for encrypted private keys.
* `list`: `dict[str, Any] | None` - Token list config. See: [Lists](lists.md).

### Usage

```python
from jam import Jam

jam = Jam(config="config.toml")
```

### Issue a token

Method: `jam.issue`

```python
token = jam.issue(
    {"id": 1, "role": "admin"},
    via="jwt",
    iss="YourService",
    exp=3600,
)
print(token)
>>> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIi...
```

### Authenticate a token

Method: `jam.authenticate`

```python
data = jam.authenticate(token, via="jwt")
print(data)
>>> {'sub': '1', 'id': 1, 'role': 'admin', 'exp': 1772132706, ...}
```

### Encrypt a token

Method: `jam.authenticate` with `via="jwe"` (JWE mode) or `jam.jwt.encrypt`.

```python
encrypted = jam.jwt.encrypt(payload={"user_id": 123, "role": "admin"})
data = jam.jwt.decrypt(encrypted)
print(data)
>>> {'user_id': 123, 'role': 'admin'}
```

### Access the module directly

`jam.jwt` exposes the configured `jam.jose.JWT` instance — every module
method is available on it:

```python
payload = jam.jwt.decode(token, validate_claims=True)
print(payload["payload"]["role"])
>>> "admin"
```

## Use out of instance

### Built

Module: `jam.jose.JWT`

Args:

* `alg`: `str | None` - Signing algorithm (JWS).
* `enc`: `str | None` - Content encryption algorithm (JWE). Creates encrypted JWT if specified.
* `secret_key`: `str | bytes | KeyLike | JWK | None` - Key for signing/encryption.
* `password`: `str | bytes | None` - Password for encrypted private keys.
* `list`: `dict[str, Any] | None` - Token list config.
* `serializer`: `BaseEncoder | type[BaseEncoder] = JsonEncoder` - JSON encoder/decoder.
* `jws`: `JWS | None` - Pre-built JWS instance. If provided, alg is ignored.
* `jwe`: `JWE | None` - Pre-built JWE instance. If provided, enc and secret_key are ignored.

```python
import os
from jam.jose import JWT

jwt = JWT(
    alg="RS256",
    secret_key=os.getenv("RSA_PRIVATE_KEY")
)
```

### Pre-built JWS/JWE instances

For full control over the underlying JWS and JWE instances, you can pass
pre-built instances to the JWT constructor:

```python
from jam.jose import JWS, JWE, JWT

# Custom JWS with specific settings
jws = JWS(alg="PS256", key=private_key)

# Custom JWE with specific settings
jwe = JWE(alg="ECDH-ES+A256KW", enc="A256GCM", key=ec_public_key)

# JWT with pre-built instances
jwt = JWT(jws=jws, jwe=jwe)
```

When using pre-built instances:

- If `jws` is provided, `alg` must be `None` (otherwise raises
  `JamConfigurationError`)
- If `jwe` is provided, `enc` must be `None` (otherwise raises
  `JamConfigurationError`)
- At least one of `alg`, `enc`, `jws`, or `jwe` must be provided

### Encode token

Method: `jwt.encode`

Args:

* `iss`: `str | None = None` - Issuer.
* `sub`: `str | None = None` - Subject.
* `aud`: `str | None = None` - Audience.
* `exp`: `int | None = None` - Lifetime in seconds.
* `nbf`: `int | None = None` - Not-before in seconds from now.
* `jti`: `str | None = None` - JWT ID.
* `header`: `dict[str, Any] | None = None` - Additional header.
* `payload`: `dict[str, Any] | None = None` - Custom data.

Returns:

`str`: Encoded JWT.

```python
token = jwt.encode(
    exp=3600,
    sub="user@email.com",
    payload={"user_id": 123}
)
```

### Decode token

Method: `jwt.decode`

Args:

* `token`: `str` - JWT token.
* `validate_claims`: `bool = True` - Validate exp/nbf.

Returns:

`dict[str, dict[str, Any]]`: Dict with `header` and `payload` keys.

Raises:

* `JamJWTExpired` - Token expired.
* `JamJWTNotYetValid` - Token not yet valid.
* `JamJWSVerificationError` - Invalid signature or token type.

```python
data = jwt.decode(token, validate_claims=True)
print(data["payload"]["sub"])
>>> "user@email.com"
```

### Encrypt token

Method: `jwt.encrypt`

Args:

* `payload`: `dict[str, Any] | str` - Data to encrypt.
* `header`: `dict[str, Any] | None = None` - Additional header.

Returns:

`str`: Encrypted JWT.

```python
encrypted = jwt.encrypt(
    payload={"data": "sensitive"},
    header={"purpose": "auth"}
)
```

### Decrypt token

Method: `jwt.decrypt`

Args:

* `token`: `str` - Encrypted JWT.

Returns:

`dict[str, Any]`: Decrypted data.

```python
data = jwt.decrypt(token=encrypted)
print(data)
>>> {"data": "sensitive"}
```

### Generate JTI

Property: `jwt.jti`

Returns:

`str`: Unique UUID for JWT ID.

```python
jti = jwt.jti
print(jti)
>>> "0c2c38d2-5dcb-4294-bb2d-0820f6ff787d"
```
