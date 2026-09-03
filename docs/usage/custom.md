---
title: Custom modules
---

Jam is designed to be extended. There are several customization points:

* custom **subjects** (`subject=`),
* custom **authorization policies** (`[jam.authz] module = "..."`),
* custom **OTP** classes (`[jam.otp] custom_module = "..."`),
* custom **OAuth2** clients (`custom_module` in a provider config),
* custom **SAML** implementations,
* subclassing any module's `Base*` class and using it standalone.

## Custom subjects

Pass your own dataclass subject to `Jam`:

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class MyUser(BaseSubject):
    id: str
    email: str = ""


jam = Jam(config="config.toml", subject=MyUser)
```

See [Subjects](/usage/subject).

## Custom authorization policies

Implement `jam.BasePolicy` and point `[jam.authz] module` to it:

```python
from jam import AuthorizationContext, BasePolicy, Principal


class MyPolicy(BasePolicy):
    def __init__(self, rules: dict) -> None:
        self._rules = rules

    def check(
        self,
        principal: Principal,
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        # your logic
        return permission in self._rules.get(principal.subject.id, [])
```

```toml
[jam.authz]
module = "my_app.policies.MyPolicy"

[jam.authz.rules]
"1" = ["profile:read", "post:create"]
```

```python
jam = Jam(config="config.toml", subject=MyUser)

if jam.authorize(user, "post:create"):
    ...
```

See [Authorization](/usage/authz).

## Custom OTP class

`[jam.otp] custom_module` selects your implementation, which must follow the
`BaseOTP` interface:

```python
from jam.otp.__base__ import BaseOTP


class MyOTP(BaseOTP):
    def at(self, factor: int | None = None) -> str:
        # your logic
        return "123456"

    def verify(self, code: str, factor: int | None = None, look_ahead: int = 1) -> bool:
        return code == self.at(factor)
```

```toml
[jam.otp]
type = "totp"
custom_module = "my_app.otp.MyOTP"
```

## Custom OAuth2 client

`custom_module` in a provider config selects the client class:

```python
from jam.oauth2 import OAuth2Client


class MyProvider(OAuth2Client):
    ...
```

```toml
[jam.oauth2.providers.myservice]
custom_module = "my_app.oauth2.MyProvider"
client_id = "$MY_CLIENT_ID"
client_secret = "$MY_CLIENT_SECRET"
auth_url = "https://example.com/oauth/authorize"
token_url = "https://example.com/oauth/token"
redirect_url = "https://example.com/callback"
```

## Custom modules via framework integrations

Framework integrations expose a `MODULE` class attribute that can be
replaced. For example, replacing the `JWT` implementation in the
[Starlette integration](/framework_integrations/starlette/):

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware

from jam.ext.starlette import JWTBackend
from jam.jose import BaseJWT

class MyJWT(BaseJWT):
    def __init__(
        self,
        secret_key: str,
    ):
        self.secret_key = secret_key

    def encode(self, payload: dict) -> str:
        # your logic
        return token

    def decode(self, token: str) -> dict:
        # your logic
        return payload

JWTBackend.MODULE = MyJWT

app = Starlette(
    middleware=[
        Middleware(
            AuthenticationMiddleware,
            backend=JWTBackend(config="config.toml")
        ),
    ],
)
```

## Extending modules standalone

Every module ships a `Base*` class (`BaseJWT`, `BaseJWS`, `BaseSession`,
`BaseOTP`, `BaseOAuth2Client`, ...). Subclass it and use your implementation
directly — the same way you would use any module:

```python
from jam.jose import BaseJWT


class MyJWT(BaseJWT):
    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def encode(self, payload: dict) -> str:
        # your logic
        return token

    def decode(self, token: str) -> dict:
        # your logic
        return payload


jwt = MyJWT(secret_key="your_secret")
token = jwt.encode(payload={"user_id": 123})
```
