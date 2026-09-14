---
title: Auth utils
---

For convenience, Jam includes some utilities for authentication mechanisms and simple encryption.


## Password hashing

### Create hash

Util: `jam.utils.hash_password`

Args:

* `password`: `str` - Password.
* `salt`: `bytes | None = None` - Some salt.
* `iterations`: `int = 100_000` - Number of iterations for hashing.
* `salt_size`: `int = 16` - Size of salt in bytes.

Returns:

`tuple[str, str]` - hex salt, hex hash

```python
from jam.utils import hash_password

some_password = "qwerty1234"
salt, hash_ = hash_password(
    password=some_password
)
print(salt)
>>> 92053744b136bed21397f25a7c19bc40
print(hash_)
>>> 0b1ee2ad3bda7c1697ae09733c96449b69c951fe425ef36b7620700f3e77f184
```

### Verify password hash

Util: `jam.utils.check_password`

Args:

* `password`: `str` - Password to check.
* `salt_hex`: `str` - Salt.
* `hash_hex`: `str` - Hash.
* `iterations`: `int = 100_000` - Number of iterations for hashing.

Returns:

`bool` - Whether the password matches the hash.

```python
from jam.utils import check_password

valid = check_password(
    password="qwerty1234",
    salt_hex=salt,
    hash_hex=hash_
)
print(valid)
>>> True
```

## Basic auth

#### Encode header

Util: `jam.utils.basic_auth_encode`

Args:

* `login`: `str` - Login.
* `password`: `str` - Password.

Returns:

`str` - Basic auth header value.

```python
from jam.utils import basic_auth_encode

auth_header = basic_auth_encode(
    login="user",
    password="password"
)
print(auth_header)
>>> "dXNlcjpwYXNzd29yZA=="
```

### Decode header

Util: `jam.utils.basic_auth_decode`

Args:

* `data`: `str`

Returns:

`tuple[str, str]` - Login, Password.

```python
from jam.utils import basic_auth_decode

login, password = basic_auth_decode(
    data="dXNlcjpwYXNzd29yZA=="
)
print(login)
>>> "user"
print(password)
>>> "password"
```

## XOR data

Util: `jam.utils.xor_my_data`

Args:

* `data`: `str` - Data to XOR.
* `key`: `str` - XOR key.

Returns:

`str` - XORed data.

```python
from jam.utils import xor_my_data

data = "secret"
key = "key"
xored = xor_my_data(data=data, key=key)
print(xored)
>>> "18001a19000d"
```
