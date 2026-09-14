---
title: Quickstart
---

The fastest way to get started with Jam. This guide uses the `Jam` facade:
configure modules in a TOML file, issue a token, authenticate it and check
permissions.

## 1. Install

```bash
pip install jamlib
```

## 2. Configure

Create `config.toml` with the modules you need:

```toml
[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[jam.authz.rules]
"profile:read" = ["*"]
"post:create" = ["is_authenticated"]
```

Values starting with `$` are read from environment variables. Set one up:

```bash
export JWT_SECRET_KEY="some-secret-key-min-32-chars"
```

## 3. Define a subject

```python
from dataclasses import dataclass

from jam import BaseSubject


@dataclass
class User(BaseSubject):
    id: str
    email: str = ""
    role: str = "user"
    is_authenticated: bool = True
```

## 4. Create the instance

```python
from jam import Jam

jam = Jam(config="config.toml", subject=User)
```

## 5. Issue a token

```python
user = User(id="1", email="user@example.com", role="admin")

token = jam.issue(
    user,
    via="jwt",
    exp=3600,
    permissions=["profile:read", "post:create"],
)
print(token)
>>> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 6. Authenticate

```python
principal = jam.authenticate(token, via="jwt")
print(type(principal.subject))  # -> <class '__main__.User'>
print(principal.subject.email)  # -> "user@example.com"
print(principal.permissions)    # -> frozenset({"profile:read", "post:create"})
```

## 7. Authorize

```python
print(jam.authorize(principal, "post:create"))  # -> True
print(jam.authorize(principal, "post:delete"))  # -> False (not in token)
```

## Next steps

* [Jam instance](/usage/jam) - `issue` / `authenticate` / `authorize`
  in detail.
* [Configuration](/configuration) - all config formats and options.
* [JWT](/usage/jose/jwt) - token details, algorithms, black/white lists.
* [PASETO](/usage/paseto), [sessions](/usage/sessions),
  [OTP](/usage/otp), [OAuth2](/usage/oauth2), [SAML](/usage/saml).
