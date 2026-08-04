---
title: JWS
---

## Use in instance

### Config


* `alg`: `str` - Signing algorithm. Available: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`.
* `key`: `str` - Secret key for signing/verify.
* `password`: `str | None` - Password for key derivation.

```toml
[jam.jose.jws]
alg = ""
key = "$JWS_SECRET_KEY"
password = "$JWS_PASSWORD"
```

### Sign data

Method: `jam.jws_sign`

Creates JWS Compact Serialization - digital signature of data.

Args:

* `alg`: `str` - Signing algorithm. Available: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`.
* `header`: `dict[str, Any] | None = None` - Additional header fields.
* `data`: `dict[str, Any] | str | bytes` - Data to sign.

Returns:

`str`: JWS in Compact Serialization format.

```python
from jam import Jam

jam = Jam(config="config.toml")

jws_token = jam.jws_sign(
    alg="RS256",
    header={"custom": "header_value"},
    data={"message": "Hello, World!"}
)
print(jws_token)
>>> eyJhbGciOiJSUzI1NiJ9.eyJtc2QiOiJIZWxsbywgV29ybGQhIn0.ABC123...
```

### Verify token

Method: `jam.jws_verify`

Verifies JWS token and returns data.

Args:

* `alg`: `str` - Algorithm for signature verification.
* `token`: `str` - JWS token.
* `validate`: `bool = True` - Validate signature.

Returns:

`dict[str, Any]`: Decoded data with keys `header`, `payload`, `signature`.

Raises:

* `JamJWSVerificationError` - Invalid signature.

```python
data = jam.jws_verify(
    alg="RS256",
    token=jws_token,
    validate=True
)
print(data)
>>> {
    'header': {'alg': 'RS256'},
    'payload': b'{"msg":"Hello, World!"}',
    'signature': b'...'
}
```

## Standalone (module)

### Create instance

Module: `jam.jose.JWS`

Args:

* `alg`: `str` - Signing algorithm.
* `key`: `str | bytes | KeyLike | JWK` - Key for signing.
* `password`: `bytes | None = None` - Password for encrypted keys.

```python
from jam.jose import JWS

jws = JWS(
    alg="ES256",
    key="-----BEGIN EC PRIVATE KEY-----..."
)
```

### Factory function

```python
from jam.jose import create_jws_instance

jws = create_jws_instance(
    alg="HS256",
    key="your-secret-key",
)
```

### Sign data

Method: `jws.sign`

Args:

* `header`: `dict[str, Any]` - JWS header.
* `data`: `dict[str, Any] | str | bytes` - Data to sign.

Returns:

`str`: JWS in Compact Serialization format.

```python
token = jws.sign(
    header={"typ": "JWT"},
    data={"user_id": 123}
)
print(token)
>>> eyJhbGciOiJFUzI1NiJ9.eyJ1c2VyX2lkIjoxMjN9.AMgVRaO2...
```

### Verify token

Method: `jws.verify`

Args:

* `token`: `str` - JWS token.
* `validate`: `bool = True` - Validate signature.

Returns:

`dict[str, Any]`: Decoded data with keys `header`, `payload`, `signature`.

Raises:

* `JamJWSVerificationError` - Invalid signature.

```python
result = jws.verify(token, validate=True)
print(result["header"])
>>> {'alg': 'ES256', 'typ': 'JWT'}
print(result["payload"])
>>> b'{"user_id":123}'
```

### Serialize compact

Method: `jws.serialize_compact`

Low-level operation for creating JWS Compact Serialization.

Args:

* `protected`: `dict[str, Any]` - Protected header.
* `payload`: `str | bytes` - Payload to sign.

Returns:

`str`: JWS string.

```python
jws_token = jws.serialize_compact(
    protected={"alg": "HS256", "custom": "value"},
    payload="Hello"
)
```

### Deserialize compact

Method: `jws.deserialize_compact`

Low-level operation for parsing JWS Compact Serialization.

Args:

* `s`: `str` - JWS string.
* `validate`: `bool = True` - Validate signature.

Returns:

`dict[str, Any]`: Parsed data.

Raises:

* `JamJWSVerificationError` - Invalid format or signature.

```python
data = jws.deserialize_compact(jws_token, validate=True)
```

### Critical header validation

JWS validates the `crit` (critical) header per RFC 7515. If a header name is
listed in `crit`, it must be a registered JOSE header name (`alg`, `typ`,
`kid`, `x5u`, `x5t`, `cty`, `crit`). Unknown critical headers cause
verification to fail.

```python
# This will fail - "unknown" is not a registered header
jws.deserialize_compact(
    "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsidW5rbm93biJ9...",
    validate=True,
)
# Raises JamJWSVerificationError: unknown_critical_header
```

### Key auto-loading

When a string is passed as `key`, JWS attempts to load it as a file path first.
If the file exists, its contents are used as the key. Otherwise, the string is
used directly as the key material.

```python
# Loads key from file if path exists
jws = JWS(alg="RS256", key="/path/to/private-key.pem")

# Uses string directly if not a valid file path
jws = JWS(alg="HS256", key="my-secret-string-key")
```

## Examples

### HMAC (HS256/384/512)

Symmetric algorithm with shared secret key.

```python
from jam.jose import JWS

jws = JWS(alg="HS256", key="your-secret-key-min-32-chars")
token = jws.sign(header={}, data={"user": "admin"})
result = jws.verify(token)
```

### RSA (RS256/384/512)

Asymmetric algorithm with RSA key pair.

```python
from jam.jose import JWS

# Sign with private key
jws = JWS(alg="RS256", key=private_key)
token = jws.sign(header={}, data={"data": "value"})

# Verify with public key
jws_verify = JWS(alg="RS256", key=public_key)
result = jws_verify.verify(token)
```

### ECDSA (ES256/384/512)

Elliptic curve for shorter signatures.

```python
from jam.jose import JWS

jws = JWS(alg="ES256", key=ec_private_key)
token = jws.sign(header={}, data={"message": "signed"})
result = jws.verify(token)
```

### RSA-PSS (PS256/384/512)

RSA algorithm with Probabilistic Signature Scheme.

```python
from jam.jose import JWS

jws = JWS(alg="PS256", key=rsa_private_key)
token = jws.sign(header={}, data={"data": "value"})
result = jws.verify(token)
```
