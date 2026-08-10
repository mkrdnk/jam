---
title: JWE
---

## Instance (jam.Jam)

### Config

```toml
[jam.jose.jwe]
alg = "RSA-OAEP"
enc = "A128CBC-HS256"
key = "$JWE_PUBLIC_KEY"
```

The configured `jam.jose.JWE` instance is exposed as `jam.jwe`:

### Encrypt data

Method: `jam.jwe.encrypt`

Creates JWE Compact Serialization - encrypted data.

Args:

* `plaintext`: `dict[str, Any] | str | bytes` - Data to encrypt. If dict, will be JSON serialized.
* `header`: `dict[str, Any] | None = None` - Additional header fields.

Returns:

`str`: JWE in Compact Serialization format.

```python
from jam import Jam

jam = Jam(config="config.toml")

jwe_token = jam.jwe.encrypt(
    plaintext={"secret": "data"},
    header={"custom": "value"}
)
print(jwe_token)
>>> eyJhbGciOiJSU0ExLjI1NiIsImVuYyI6IkExMjhHQ1Mtc2hhMjU2In0...
```

### Decrypt data

Method: `jam.jwe.decrypt`

Decrypts JWE token.

Args:

* `token`: `str` - JWE token.

Returns:

`bytes`: Decrypted data.

Raises:

* `JamJWEDecryptionError` - Decryption failed.
* `JamJWEInvalidFormatError` - Invalid token format.

```python
data = jam.jwe.decrypt(token=jwe_token)
print(data)
>>> b'{"secret": "data"}'
```

### Encrypted tokens in the facade

Encrypted JWTs issued with `jam.issue` are authenticated with
`jam.authenticate(via="jwe")` when JWE mode is configured on `[jam.jose.jwt]`:

## Standalone (module)

### Create instance

Module: `jam.jose.JWE`

Args:

* `alg`: `str` - Key management algorithm.
* `enc`: `str` - Content encryption algorithm.
* `key`: `str | bytes | KeyLike | JWK` - Key for encryption/decryption.
* `password`: `bytes | None = None` - Password for PBES2 algorithms.
* `serializer`: `BaseEncoder | type[BaseEncoder] = JsonEncoder` - Serializer.

```python
from jam.jose import JWE

jwe = JWE(
    alg="RSA-OAEP",
    enc="A128CBC-HS256",
    key=rsa_public_key
)
```

### Factory function

```python
from jam.jose import create_jwe_instance

jwe = create_jwe_instance(
    alg="A256KW",
    enc="A256GCM",
    key="your-256-bit-key-here!!",
)
```

### Encrypt data

Method: `jwe.encrypt`

Args:

* `plaintext`: `dict[str, Any] | str | bytes` - Data to encrypt. If dict, will be JSON serialized.
* `header`: `dict[str, Any] | None = None` - Additional JWE header fields.

Returns:

`str`: JWE in Compact Serialization format.

```python
jwe_token = jwe.encrypt(
    plaintext={"user_id": 123, "email": "user@example.com"},
    header={"zip": "DEF"}  # Compression header
)
```

### Decrypt data

Method: `jwe.decrypt`

Args:

* `token`: `str` - JWE token.

Returns:

`bytes`: Decrypted data (raw bytes).

Raises:

* `JamJWEDecryptionError` - Decryption failed.
* `JamJWEInvalidFormatError` - Invalid token format.

```python
data = jwe.decrypt(token=jwe_token)
print(data)
>>> b'{"user_id": 123, "email": "user@example.com"}'
```

## Encryption flow

JWE Compact Serialization format:

```
BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)
```

### Steps

1. **Generate CEK** - Random Content Encryption Key is generated
2. **Key Management** - CEK is encrypted using selected algorithm
3. **Content Encryption** - Payload is encrypted using CEK
4. **Serialization** - All components are base64url encoded

## Examples

### RSA-OAEP + AES-CBC-HS

Classic asymmetric encryption combination.

```python
from jam.jose import JWE

# Encrypt with public key
jwe = JWE(
    alg="RSA-OAEP",
    enc="A128CBC-HS256",
    key=rsa_public_key
)
token = jwe.encrypt(plaintext={"data": "sensitive"})

# Decrypt with private key
jwe_dec = JWE(
    alg="RSA-OAEP",
    enc="A128CBC-HS256",
    key=rsa_private_key
)
data = jwe_dec.decrypt(token)
```

### AES Key Wrap + AES-GCM

Symmetric encryption with shared key.

```python
from jam.jose import JWE

jwe = JWE(
    alg="A256KW",
    enc="A256GCM",
    key="your-32-byte-secret-key-here!!"
)
token = jwe.encrypt(plaintext="Secret message")

data = jwe.decrypt(token)
```

### ECDH-ES

Ephemeral-static ECDH for perfect forward secrecy.

```python
from jam.jose import JWE

jwe = JWE(
    alg="ECDH-ES",
    enc="A128CBC-HS256",
    key=ec_public_key
)
token = jwe.encrypt(plaintext={"session": "data"})

# Decrypt with recipient's private key
jwe_dec = JWE(
    alg="ECDH-ES",
    enc="A128CBC-HS256",
    key=ec_private_key
)
data = jwe_dec.decrypt(token)
```

### PBES2 (Password-Based)

Password-based encryption.

```python
from jam.jose import JWE

jwe = JWE(
    alg="PBES2-HS512+A256KW",
    enc="A256CBC-HS512",
    key=None,
    password=b"user_password"
)
token = jwe.encrypt(plaintext={"data": "password_encrypted"})

# Decrypt with same password
jwe_dec = JWE(
    alg="PBES2-HS512+A256KW",
    enc="A256CBC-HS512",
    key=None,
    password=b"user_password"
)
data = jwe_dec.decrypt(token)
```
