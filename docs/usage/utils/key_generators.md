---
title: Key generators
---

For your convenience, Jam includes several utilities for generating keys.

!!! tip
    All of these utilities are available in the **Jam CLI**. See the [documentation](/usage/cli).

## Symmetric key generator

Util: `jam.utils.generate_symmetric_key`

Args:

* `n`: `int = 32` - Key length in bytes.

Returns:

`str` - Symmetric key.

```python
from jam.utils import generate_symmetric_key

key = generate_symmetric_key()
print(key)
>>> KwMcnHqffc-jEKLrCdk93pNBHrTgyFH-MeWu2Z_udco
```

## AES key generator

Util: `jam.utils.generate_aes_key`

Returns:

`bytes`: AES key.

```python
from jam.utils import generate_aes_key

key = generate_aes_key()
print(key)
>>> b'NMuwX-O7wgSrOv8NMXkjFrMAwKQsUpWpnkmEnAM0TzE='
```

## ED keypair

Utils:

* `jam.utils.generate_ed25519_keypair`
* `jam.utils.generate_ecdsa_p384_keypair`

Returns:

`dict[str, str]` - Dict in format `{"private": KEY, "public": KEY}`.

```python
from jam.utils import generate_ed25519_keypair

ed25519_keypair = generate_ed25519_keypair()
print(ed25519_keypair)
>>> {'private': '', 'public': ''}
####
from jam.utils import generate_ecdsa_p384_keypair

ecdsa_p384_keypair = generate_ecdsa_p384_keypair()
print(ecdsa_p384_keypair)
>>> {'private': '', 'public': ''}
```

## OTP specific key

Utils:

* `jam.utils.generate_otp_key`

Args:

* `entropy_bits`: `int = 128` - Number of entropy bits to use for key generation.

Returns:

`str` - OTP key.

* `jam.utils.otp_key_from_string`

Args:

* `s`: `str` - Some string to generate.

Returns:

`str` - OTP Key.


```python
from jam.utils import generate_otp_key

key = generate_otp_key()
print(key)
>>> SSDEWUXGHUG3XG53JMVYO555WI

### from string
from jam.utils import otp_key_from_string

key = otp_key_from_string("someusername@example.com")
print(key)
>>> CUK2QXKSV5DSNPI46DPK46TYYRIMX7QK
```

## RSA keypair

Util `jam.utils.generate_rsa_key_pair`

Args:

* `key_size`: `int = 2048` - Key size in bits.

Returns:

`dict[str, str]` - Dict in format `{"private": KEY, "public": KEY}`

```python
from jam.utils import generate_rsa_key_pair

rsa_keypair = generate_rsa_key_pair()
print(rsa_keypair)
>>> {'private': '', 'public': ''}
```
