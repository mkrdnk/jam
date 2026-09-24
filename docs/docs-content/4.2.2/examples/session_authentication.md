# Session authentication with Litestar

This Litestar example uses a server-side Jam session. The browser receives an
opaque session ID in an HttpOnly cookie, while the authenticated subject and
permissions remain in server-controlled storage.

It demonstrates:

- `JamPlugin` authentication middleware;
- a cookie `CredentialSource`;
- a typed subject and `Principal`;
- a permission guard;
- login and complete server-side logout.

## Install and configure

```bash
pip install litestar "jamlib[litestar,json]" uvicorn
export JAM_SESSION_AES_SECRET="$(
  python -c \
  'from jam.utils import generate_aes_key; print(generate_aes_key().decode())'
)"
```

Create `config.toml`:

```toml
[jam.session]
type = "json"
json_path = "sessions.json"
session_key = "users"
is_session_crypt = true
session_aes_secret = "$JAM_SESSION_AES_SECRET"
```

The JSON backend makes the example runnable without another service. Use the
Redis backend for multiple application instances and server-enforced TTLs.

!!! tip "Other configuration formats"
    `Jam` also accepts a Python dictionary or a YAML or JSON file. File
    configuration supports `$VAR` and `${VAR:-default}` substitutions.

## Create the Litestar application

Create `app.py`:

```python
from dataclasses import dataclass
from secrets import compare_digest

from litestar import Litestar, Request, Response, get, post
from litestar.datastructures import Cookie
from litestar.exceptions import NotAuthorizedException
from pydantic import BaseModel

from jam import BaseSubject, Jam
from jam.authz import Principal
from jam.ext.litestar import (
    CredentialSource,
    JamPlugin,
    permission_guard,
)


@dataclass
class User(BaseSubject):
    id: str
    username: str
    role: str


jam = Jam(config="config.toml", subject=User)

DEMO_USER = {
    "id": "user-1",
    "username": "alice",
    "password": "change-me",
    "role": "editor",
}


class LoginRequest(BaseModel):
    username: str
    password: str


@post("/login", sync_to_thread=True)
def login(data: LoginRequest) -> Response[None]:
    username_valid = compare_digest(
        data.username.encode(),
        DEMO_USER["username"].encode(),
    )
    password_valid = compare_digest(
        data.password.encode(),
        DEMO_USER["password"].encode(),
    )
    if not username_valid or not password_valid:
        raise NotAuthorizedException("Invalid username or password.")

    session_id = jam.issue(
        User(
            id=DEMO_USER["id"],
            username=DEMO_USER["username"],
            role=DEMO_USER["role"],
        ),
        via="session",
        permissions=["profile:read"],
    )
    return Response(
        content=None,
        status_code=204,
        cookies=[
            Cookie(
                key="session",
                value=session_id,
                max_age=3600,
                httponly=True,
                secure=False,  # Use True behind HTTPS.
                samesite="lax",
            )
        ],
    )


@get(
    "/me",
    guards=[permission_guard(jam, "profile:read")],
    sync_to_thread=False,
)
def me(request: Request) -> dict:
    principal: Principal[User] = request.user
    return {
        "id": principal.subject.id,
        "username": principal.subject.username,
        "role": principal.subject.role,
        "permissions": sorted(principal.permissions),
    }


@post(
    "/logout",
    guards=[permission_guard(jam, "profile:read")],
    sync_to_thread=True,
)
def logout(request: Request) -> Response[None]:
    session_id = request.auth.token
    if session_id is not None:
        jam.session.delete(session_id)

    response = Response(content=None, status_code=204)
    response.delete_cookie("session")
    return response


app = Litestar(
    route_handlers=[login, me, logout],
    plugins=[
        JamPlugin(
            jam,
            via="session",
            sources=[CredentialSource.cookie("session")],
            exclude=["/login"],
        )
    ],
)
```

## How the integration works

`JamPlugin` registers the configured `Jam` instance with Litestar dependency
injection and installs authentication middleware. The middleware reads the
`session` cookie, calls `jam.authenticate(..., via="session")`, and exposes:

| Litestar value | Jam value |
| --- | --- |
| `request.user` | The authenticated `Principal[User]`, or `None`. |
| `request.auth` | The complete authentication result, including the session ID. |
| `request.state.jam` | The configured Jam instance. |
| `request.state.principal` | The authenticated principal. |

The login route is excluded from middleware because no credential exists yet.
`permission_guard()` protects `/me` and `/logout`: missing authentication is
rejected, and the session must grant `profile:read`.

`jam.issue(..., via="session")` stores the subject and permissions on the
server. Only the opaque ID is sent to the browser. Logout deletes both sides:
the server record and the browser cookie.

## Run the flow

```bash
uvicorn app:app --reload

curl -i -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"change-me"}' \
  http://127.0.0.1:8000/login

curl -b cookies.txt http://127.0.0.1:8000/me

curl -i -b cookies.txt -c cookies.txt \
  -X POST http://127.0.0.1:8000/logout
```

For production, hash passwords, use `Secure` cookies over HTTPS, protect
state-changing routes against CSRF, regenerate IDs after privilege changes,
and use Redis or a custom persistent backend with an appropriate TTL.
