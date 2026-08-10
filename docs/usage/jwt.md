---
title: JWT
---

!!! Deprecated
    `jam.jwt` is deprecated, use `jam.jose`. This page is kept for historical
    reference. See the current [JWT documentation](/usage/jose/jwt).

The `jam.jwt` module was merged into `jam.jose` in Jam 4.0. Use
`jam.jose.JWT` (standalone) or configure `[jam.jose.jwt]` in your config.

## Use in instance

### Config

```toml
[jam.jose.jwt]
alg = "HS256"
secret_key = "YOURSECRETKEY"
password = "PASSWORD_FOR_PRIVATE_KEY"

[jam.jose.jwt.list]
type = "black"
backend = "redis"
redis_uri = "redis://localhost:6379"
```

### Usage

```python
from jam import Jam

jam = Jam(config="config.toml")
```

### Issue a token

Method: `jam.issue`

```python
token = jam.issue({"user": 1, "role": "admin"}, via="jwt", exp=3600)
print(token)
>>> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Authenticate a token

Method: `jam.authenticate`

```python
data = jam.authenticate(token, via="jwt")
print(data)
>>> {'sub': '1', 'user': 1, 'role': 'admin', 'exp': 1772120451, ...}
```

### Access the module directly

`jam.jwt` exposes the underlying `jam.jose.JWT` instance:

```python
payload = jam.jwt.decode(token)["payload"]
print(payload)
>>> {'sub': '1', 'user': 1, 'role': 'admin', 'exp': 1772120451, ...}
```

## Use out of instance

Module: `jam.jose.JWT` — see the [JOSE JWT documentation](/usage/jose/jwt)
for the full standalone API.
