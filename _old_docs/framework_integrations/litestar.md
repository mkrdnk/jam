# Litestar

Install the extra:

```bash
pip install "jamlib[litestar]"
```

`JamPlugin` registers the configured instance as the `jam` dependency and,
by default, installs authentication middleware.

```python
from litestar import Litestar, Request, get

from jam import Jam
from jam.authz import Principal
from jam.ext.litestar import JamPlugin, permission_guard


jam = Jam("config.toml")


@get("/me")
async def me(request: Request) -> dict:
    principal: Principal = request.user
    return principal.subject


@get("/posts", guards=[permission_guard(jam, "post:read")])
async def posts() -> list:
    return []


app = Litestar(
    route_handlers=[me, posts],
    plugins=[JamPlugin(jam)],
)
```

Handlers receive the complete `Principal` as `request.user`.
`request.auth` is the shared `AuthenticationResult`. The same values are also
available as `request.state.principal`, `authentication`, and `jam`.

Sources, explicit credential type, public route exclusions, and invalid-token
behavior are configured per plugin instance:

```python
from jam.ext.litestar import CredentialSource, JamPlugin

plugin = JamPlugin(
    jam,
    sources=[
        CredentialSource.bearer(),
        CredentialSource.cookie("session"),
    ],
    exclude=["/health"],
    reject_invalid=True,
)
```

Use `JamPlugin(jam, middleware=False)` when only dependency injection is
needed. Unlike the previous adapters, middleware configuration is not stored
on class attributes, so multiple apps remain isolated.
