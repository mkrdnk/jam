---
title: JWK
---

## TypedDicts

### JWKCommon

Common JWK parameters shared across all key types.

```python
from jam.jose import JWKCommon

key: JWKCommon = {
    "kty": "RSA",           # Required. Key type: RSA, EC, oct
    "use": "sig",           # Public key use: "sig" or "enc"
    "key_ops": ["sign"],    # Intended key operations
    "alg": "RS256",         # Intended algorithm
    "kid": "key-id",        # Unique key identifier
    "x5u": "https://...",   # X.509 URL
    "x5c": "MIID...",       # X.509 certificate chain (base64)
    "x5t": "abc...",        # X.509 SHA-1 thumbprint
    "x5t_S256": "xyz...",   # X.509 SHA-256 thumbprint
}
```

### JWKRSA

RSA key parameters (extends `JWKCommon`).

```python
from jam.jose import JWKRSA

# Public key
rsa_pub: JWKRSA = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuu...",   # Modulus (base64url)
    "e": "AQAB",                    # Exponent (base64url)
}

# Private key (requires all CRT parameters per RFC 7518)
rsa_priv: JWKRSA = {
    "kty": "RSA",
    "n": "...", "e": "AQAB",
    "d": "...",    # Private exponent
    "p": "...",    # First prime factor
    "q": "...",    # Second prime factor
    "dp": "...",   # d mod (p-1)
    "dq": "...",   # d mod (q-1)
    "qi": "...",   # q^(-1) mod p
}
```

!!! warning "RSA private key validation"
    When `d` is present, all CRT parameters (`p`, `q`, `dp`, `dq`, `qi`) are
    required. Missing any of them raises `JamJWKValidationError` per RFC 7518
    Section 6.3.2.

### JWKEC

Elliptic curve key parameters (extends `JWKCommon`).

```python
from jam.jose import JWKEC

ec_key: JWKEC = {
    "kty": "EC",
    "crv": "P-256",    # Supported: P-256, P-384, P-521
    "x": "f83OJ3D...",  # X coordinate (base64url)
    "y": "x_FEzRu...",  # Y coordinate (base64url)
    "d": "...",         # Private key (optional, base64url)
}
```

### JWKOct

Symmetric (octet sequence) key parameters (extends `JWKCommon`).

```python
from jam.jose import JWKOct

oct_key: JWKOct = {
    "kty": "oct",
    "k": "c2VjcmV0LWtleS0zMi1ieXRlcy1sb25n",  # Key value (base64url)
}
```

---

## Standalone (module)

### JWK - JSON Web Key

JWK represents a cryptographic key in JSON format.

#### Create from dict

Method: `JWK.from_dict`

Creates JWK from dictionary.

Args:

* `data`: `dict[str, Any]` - JWK dict. Required field `kty`.

Returns:

`JWK`: Validated JWK instance.

Raises:

* `JamJWKValidationError` - If JWK is invalid.

```python
from jam.jose import JWK

# Symmetric key (oct)
oct_key = JWK.from_dict({
    "kty": "oct",
    "k": "GawgguFyGrWKav7AX4VKUg",  # base64url encoded key
    "kid": "my-signing-key"
})

# RSA key
rsa_key = JWK.from_dict({
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbW...",
    "e": "AQAB",
    "kid": "rsa-key-1"
})

# EC key
ec_key = JWK.from_dict({
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "kid": "ec-key-1"
})
```

#### Validate

Static method: `JWK.validate`

Validates and creates JWK from dict.

Args:

* `data`: `dict[str, Any]` - JWK dict.

Returns:

`JWK`: Validated instance.

```python
jwk = JWK.validate({"kty": "oct", "k": "base64key"})
```

### Properties

JWK has the following properties:

* `kty`: `str` - Key Type. Possible values: `RSA`, `EC`, `oct`.
* `alg`: `str | None` - Algorithm. Specifies algorithm to use with the key.
* `kid`: `str | None` - Key ID. Unique key identifier.

```python
jwk = JWK.from_dict({"kty": "oct", "k": "key", "kid": "key1"})
print(jwk.kty)  # "oct"
print(jwk.alg)  # None
print(jwk.kid)  # "key1"
```

All JWK parameters are accessible via `to_dict()`:

| Parameter | Type | Description |
|-----------|------|-------------|
| `kty` | `str` | Key Type (RSA, EC, oct) |
| `use` | `str` | Public key use (`sig`, `enc`) |
| `key_ops` | `list[str]` | Intended key operations |
| `alg` | `str` | Intended algorithm |
| `kid` | `str` | Key ID |
| `x5u` | `str` | X.509 URL |
| `x5c` | `str` | X.509 certificate chain |
| `x5t` | `str` | X.509 SHA-1 thumbprint |
| `x5t#S256` | `str` | X.509 SHA-256 thumbprint |

### Sign data

Method: `jwk.sign`

Signs data using JWK.

Args:

* `data`: `bytes` - Data to sign.
* `alg`: `str | None = None` - Signing algorithm. If `None`, uses `alg` from JWK or default for kty.

Returns:

`str`: JWS in Compact Serialization format.

Raises:

* `JamJWSVerificationError` - If signing failed.

```python
jwk = JWK.from_dict({"kty": "oct", "k": "your-secret-key-32-bytes-long"})
token = jwk.sign(b"data to sign", alg="HS256")
```

### Verify token

Method: `jwk.verify`

Verifies JWS token using JWK.

Args:

* `token`: `str` - JWS token.
* `alg`: `str | None = None` - Algorithm. If `None`, uses from token header.

Returns:

`dict[str, Any]`: Parsed data with keys `header`, `payload`.

Raises:

* `JamJWSVerificationError` - If verification failed.

```python
result = jwk.verify(token)
print(result["payload"])
>>> b'data to sign'
```

### Convert to dict

Method: `jwk.to_dict`

Converts JWK back to dictionary.

Returns:

`dict[str, Any]`: JWK dict.

```python
jwk_dict = jwk.to_dict()
print(jwk_dict)
>>> {'kty': 'oct', 'k': 'your-secret-key-32-bytes-long', 'kid': 'key1'}
```

---

### JWKSet - Set of Keys

JWKSet represents a set of JWK keys.

#### Create from dict

Method: `JWKSet.from_dict`

Creates JWKSet from dictionary.

Args:

* `data`: `dict[str, Any]` - JWKSet dict with `keys` key.

Returns:

`JWKSet`: Validated instance.

Raises:

* `JamJWKValidationError` - If data is invalid.

```python
from jam.jose import JWKSet

jwks = JWKSet.from_dict({
    "keys": [
        {"kty": "oct", "k": "key1", "kid": "1"},
        {"kty": "oct", "k": "key2", "kid": "2"},
        {"kty": "RSA", "n": "...", "e": "AQAB", "kid": "rsa-key"}
    ]
})
```

#### Get by kid

Method: `jwks.get_by_kid`

Gets JWK by Key ID.

Args:

* `kid`: `str` - Key ID.

Returns:

`dict[str, Any] | None`: JWK dict or `None` if not found.

```python
key = jwks.get_by_kid("1")
if key:
    jwk = JWK.from_dict(key)
```

#### Get by kty

Method: `jwks.get_by_kty`

Gets all JWKs with specified Key Type.

Args:

* `kty`: `str` - Key Type (`RSA`, `EC`, `oct`).

Returns:

`list[dict[str, Any]]`: List of JWK dicts.

```python
symmetric_keys = jwks.get_by_kty("oct")
rsa_keys = jwks.get_by_kty("RSA")
```

#### Filter

Method: `jwks.filter`

Filters JWKs by criteria.

Args:

* `**criteria`: Filter criteria (`kty`, `use`, `alg`, `key_ops`, `kid`).

Returns:

`list[dict[str, Any]]`: List of matching JWK dicts.

```python
# Find keys by multiple criteria
keys = jwks.filter(kty="RSA", use="sig")
```

#### Convert to dict

Method: `jwks.to_dict`

Converts JWKSet to dictionary.

Returns:

`dict[str, Any]`: JWKSet dict.

```python
jwks_dict = jwks.to_dict()
```

## JWK Key Types

### oct - Symmetric Key

Symmetric key for HMAC algorithms.

```python
from jam.jose import JWK

# Create
jwk = JWK.from_dict({
    "kty": "oct",
    "k": "c2VjcmV0LWtleS0zMi1ieXRlcy1sb25n",  # base64url encoded
    "kid": "hmac-key"
})

# Use for HMAC
token = jwk.sign(b"data", alg="HS256")
result = jwk.verify(token)
```

### RSA

Asymmetric RSA key for RSA and RSA-PSS algorithms.

```python
from jam.jose import JWK

rsa_jwk = JWK.from_dict({
    "kty": "RSA",
    "n": "...",
    "e": "AQAB",
    "d": "...",  # private key only if needed
    "p": "...",
    "q": "...",
    "dp": "...",
    "dq": "...",
    "qi": "...",
    "kid": "rsa-key"
})

# Sign
token = rsa_jwk.sign(b"data", alg="RS256")
result = rsa_jwk.verify(token)
```

### EC - Elliptic Curve

Elliptic curve key for ECDSA algorithms.

```python
from jam.jose import JWK

ec_jwk = JWK.from_dict({
    "kty": "EC",
    "crv": "P-256",  # or P-384, P-521
    "x": "...",
    "y": "...",
    "d": "...",  # private key only if needed
    "kid": "ec-key"
})

# Sign
token = ec_jwk.sign(b"data", alg="ES256")
result = ec_jwk.verify(token)
```

## Key type-specific classes

Typed key classes are exported for static type checking:

```python
from jam.jose import JWKRSA, JWKEC, JWKOct

# These are TypedDicts for type annotations
def process_rsa_key(key: JWKRSA) -> None:
    ...

def process_ec_key(key: JWKEC) -> None:
    ...

def process_symmetric_key(key: JWKOct) -> None:
    ...
```
