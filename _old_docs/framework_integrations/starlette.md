# Starlette

Install the extra:

```bash
pip install "jamlib[starlette]"
```

`JamAuthBackend` is a standard Starlette authentication backend. It uses the
same configured `Jam` instance for JWT, JWE, PASETO, and sessions; credential
type detection is handled by `Jam.authenticate()`.

```python
from starlette.applications import Starlette
from starlette.authentication import requires
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from jam import Jam
from jam.ext.starlette import JamAuthBackend


jam = Jam("config.toml")


@requires("post:read")
async def posts(request):
    principal = request.user.principal
    return JSONResponse({"subject": principal.subject})


app = Starlette(
    routes=[Route("/posts", posts)],
    middleware=[
        Middleware(
            AuthenticationMiddleware,
            backend=JamAuthBackend(jam),
        )
    ],
)
```

The default source is `Authorization: Bearer <credential>`. Sources are
ordered and composable:

```python
from jam.ext.starlette import CredentialSource, JamAuthBackend

backend = JamAuthBackend(
    jam,
    sources=[
        CredentialSource.bearer(),
        CredentialSource.cookie("session"),
        CredentialSource.header("X-API-Token"),
    ],
)
```

On success:

- `request.user` is a `JamUser`;
- `request.user.principal` is the complete `Principal`;
- `request.auth.scopes` contains `authenticated` and credential permissions;
- `request.state.jam`, `principal`, and `authentication` are available.

Invalid credentials are rejected by default. Set `reject_invalid=False` only
when an invalid credential should be treated as anonymous.
