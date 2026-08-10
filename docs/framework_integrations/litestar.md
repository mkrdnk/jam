---
title: Jam + Litestar = <3
---

# Litestar integration

Integration with Litestar is implemented by [plugins](https://docs.litestar.dev/2/usage/plugins/index.html).

## How it works

Plugins generally do two things:

* Create a middleware for a specific authorization type.
* Add an authorization module to Litestar DI.

Example:

```python
from litestar import Litestar
from jam.ext.litestar import JWTPlugin, SimpleUser

app = Litestar(
    plugins=[JWTPlugin(
        config="config.toml",
        cookie_name="JWT",  # for example
        user=SimpleUser
    )]
)

# ---
## And now we can use JWT from DI
from litestar import post, Response
from jam.jose import JWT

@post("/login")
async def login(login: str, password: str, jwt: JWT) -> Response:
    # check login and password
    token = jwt.encode(  # use JWT from DI
        payload={"username": login}
    )
    response = Response({"token": token})
    response.set_cookie("jwt", token)
    return response
    
# Middleware by JamPlugin check cookie "jwt"
# (because it has `cookie_name="jwt"` at config)
from litestar import get, Request
from litestar.exceptions import HTTPException

@get("/user")
async def get_user(request: Request) -> dict:
    if not request.user:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return request.user.payload  # For more informations about the user, see Users documentation in Jam and Litestar docs
```

## Setup plugins

All plugins are installed in the same way; you simply pass them to `Litestar(plugins=[])` with the necessary parameters. For more information, see the [Litestar plugin documentation](https://docs.litestar.dev/2/usage/plugins/index.html).

### Plugin configuration

The plugins use the standard Jam configuration, along with some additional settings:

* `config`: `str | dict[str, Any] | None = None` - [Standard Jam configuration](/configuration).
* `pointer`: `str` - [Pointer](/configuration/#pointer-str-jam) for config.
* other plugin specific settings, see for each plugin.

```python
import os
from litestar import Litestar
from jam.ext.litestar import PASETOPlugin  # for example

config = {
    "paseto": {
        "version": "v4",
        "purpose": "local",
        "secret_key": os.getenv("PASETO_KEY")
    }
}

app = Litestar(
    plugins=[
        PASETOPlugin(
            config=config,
            header_name="Authorization",
            middleware=False
        ),
    ],
)
```

## Users

In Litestar, [user classes](https://docs.litestar.dev/2/usage/security/abstract-authentication-middleware.html#id2) included in the `request` are used for authentication. Jam also uses this concept to facilitate integration.

### Create user model

Users are created using the abstract `base_user` class, in which you must implement the `from_payload` `classmethod`, which takes data from a token or session as input and converts it into a class:

```python
from jam.ext.litestar import BaseUser

# Let's say we're using a payload
# like this for authentication:
example_payload = {
    "id": 123
    "username": "some_username",
    "role": "role"
}

# Create your own user
@dataclass
class MyUser(BaseUser):
    id: int
    username: str
    role: str
    
    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "MyUser":
        return cls(
            id=payload["id"],
            username=payload["username"],
            role=payload["role"],
        )
        
app = Litestar(
    plugins=[
        JWTPlugin(
            config=config,
            cookie_name="jwt",
            user=MyUser
        )
    ],
)
```

After that, we can use this user directly from `request`:

```python
from litestar import get, Request

@get("/profile")
async def get_profile(request: Request) -> MyUser | None:
    if not request.user:
        return None
    else:
      return request.user
```

### Simple user
If you don't need complex user logic, you can use the `SimpleUser` class. It's a class with a single attribute, `payload`: `dict[str, Any]`, which holds the entire payload.

Example:

```python
from litestar import Litestar, get, Request
from jam.ext.litestar import SessionsPlugin, SimpleUser


@get("/profile")
async def get_profile(request: Request) -> dict | None:
    if not request.user:
        return None
    else:
        return request.user.payload

app = Litestar(
    routes=[get_profile],
    plugins=[
        SessionsPlugin(
            config=config,
            cookie_name="jwt",
            user=SimpleUser
        )
    ],
)
```

## JWT Plugin

Module: `jam.ext.litestar.JWTPlugin`

Args:

* `config`: `str | dict[str, Any] | None = None` - Jam config.
* `pointer`: `str` - Config pointer.
* `cookie_name`: `str | None = None` - Cookie to check, if `middleware=True`.
* `header_name`: `str | None = None` - Header to check, if `middleware=True`.
* `middleware`: `bool = True` - Enable/disable middleware.
* `bearer`: `bool = False` - Use bearer prefix for token (e.g. "Bearer ").
* `use_list`: `bool = False` - Use token black/white list.
* `user`: `type[BaseUser] | None = None` - User for request.

!!! tip
    This plugin added `jwt`: `jam.jwt.JWT` to Litestar DI.
  
```python
from litestar import Litestar
from jam.ext.litestar import JWTPlugin, SimpleUser


app = Litestar(
    plugins=[
        JWTPlugin(
            config=config,
            cookie_name="jwt",
            user=SimpleUser
        )
    ],
)
```

## PASETO Plugin

Module: `jam.ext.litestar.PASETOPlugin`

Args:

* `config`: `str | dict[str, Any] | None = None` - Jam config.
* `pointer`: `str` - Config pointer.
* `cookie_name`: `str | None = None` - Cookie to check, if `middleware=True`.
* `header_name`: `str | None = None` - Header to check, if `middleware=True`.
* `bearer`: `bool = False` - Use bearer prefix for token (e.g. "Bearer").
* `middleware`: `bool = True` - Enable/disable middleware.
* `user`: `type[BaseUser] | None = None` - User for request.

!!! tip
    This plugin added `paseto`: `jam.paseto.PASETOv*` to Litestar DI.
  
```python
from litestar import Litestar
from jam.ext.litestar import PASETOPlugin, SimpleUser


app = Litestar(
    plugins=[
        PASETOPlugin(
            config=config,
            header_name="Authorization",
            user=SimpleUser
        )
    ],
)
```

## Server side sessions plugin

Module: `jam.ext.litestar.SessionPlugin`

Args:

* `config`: `str | dict[str, Any] | None = None` - Jam config.
* `pointer`: `str` - Config pointer.
* `cookie_name`: `str | None = None` - Cookie to check, if `middleware=True`.
* `header_name`: `str | None = None` - Header to check, if `middleware=True`.
* `bearer`: `bool = False` - Use bearer prefix for token (e.g. "Bearer").
* `middleware`: `bool = True` - Enable/disable middleware.
* `user`: `type[BaseUser] | None = None` - User for request.

!!! tip
    This plugin added `session`: `jam.aio.sessions.*` to Litestar DI.

```python
from litestar import Litestar
from jam.ext.litestar import SessionPlugin, SimpleUser


app = Litestar(
    plugins=[
        SessionPlugin(
            config=config,
            cookie_name="session",
            user=SimpleUser
        )
    ],
)
```

## OAuth2 Plugin

Module: `jam.ext.litestar.OAuth2Plugin`

Args:

* `config`: `str | dict[str, Any] | None = None` - Jam config.
* `pointer`: `str` - Config pointer.

!!! tip
    This plugin added `oauth2`: `jam.oauth2.*` to Litestar DI.
    And this plugin does not add middleware!
    
```python
from litestar import Litestar
from jam.ext.litestar import OAuth2Plugin


app = Litestar(
    plugins=[
        OAuth2Plugin(
            config=config,
        )
    ],
)
```
