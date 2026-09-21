# FastAPI application with JWT and authorization

This example builds a small FastAPI application that demonstrates the main
Jam authentication and authorization concepts together:

- a typed `Subject` representing the user;
- a signed JWT with standard and application-specific claims;
- a `Principal` created from the authenticated JWT;
- permissions carried by the credential;
- server-side authorization rules;
- request-specific `AuthorizationContext`;
- required, optional, and permission-aware FastAPI dependencies.

The application uses in-memory users and posts so that the complete flow fits
in one file. The final section explains what must change before using the
pattern in production.

## Install the dependencies

Create a directory and virtual environment:

```bash
mkdir fastapi-jwt-example
cd fastapi-jwt-example

python -m venv .venv
source .venv/bin/activate
```

Install Jam with its FastAPI integration and an ASGI server:

```bash
pip install "jamlib[fastapi]" uvicorn
```

## Configure the signing secret

This example signs tokens with `HS256`. Token creation and verification use
the same secret. Generate a random secret and expose it through the
environment:

```bash
export JWT_SECRET_KEY="$(python -c \
  'from jam.utils import generate_symmetric_key; print(generate_symmetric_key())')"
```

Alternatively, install [Jam CLI](/latest/dev/cli) and generate the key in a
file:

```bash
pip install "jamlib[cli]"
jam keys symmetric --bytes 32 --out jwt.key
export JWT_SECRET_KEY="$(cat jwt.key)"
```

Keep the same secret between application restarts if existing tokens must
remain valid. In production, load it from a secret manager instead of source
control.

## Create the configuration

Create `config.toml` next to the application:

```toml
[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[[jam.authz.rules]]
effect = "allow"
permissions = ["post:edit"]

[jam.authz.rules.when]
all = [
  { field = "token.tenant", operator = "eq", value = "@context.attributes.tenant" },
  { field = "context.resource.author_id", operator = "eq", value = "@subject.id" },
]

[[jam.authz.rules]]
effect = "allow"
permissions = ["post:edit"]

[jam.authz.rules.when]
all = [
  { field = "token.tenant", operator = "eq", value = "@context.attributes.tenant" },
  { field = "subject.role", operator = "eq", value = "admin" },
]

[[jam.authz.rules]]
effect = "deny"
permissions = ["post:edit"]

[jam.authz.rules.when]
field = "context.resource.locked"
operator = "eq"
value = true
```

`$JWT_SECRET_KEY` is replaced with the environment variable when Jam reads
the file. Keeping secrets out of the file makes it safe to commit the
non-secret configuration.

!!! tip "Configuration is not limited to TOML"
    `Jam` accepts a Python dictionary or a path to a TOML, YAML, or JSON file.
    File-based configuration supports environment substitutions such as
    `$JWT_SECRET_KEY` and `${JWT_SECRET_KEY:-development-default}`. TOML is
    used here because it keeps the application code focused on behavior.

## Create the application

Create `app.py`:

```python
import os
from dataclasses import dataclass
from secrets import compare_digest, token_urlsafe
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel

from jam import BaseSubject, Jam
from jam.authz import AuthorizationContext, Principal
from jam.ext.fastapi import JamAuth


JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY must be set")


@dataclass
class User(BaseSubject):
    id: str
    username: str
    role: str


jam = Jam(
    config="config.toml",
    subject=User,
)
auth = JamAuth(jam, via="jwt")
app = FastAPI(title="Jam JWT and authorization example")


# A real application loads users and password hashes from a database.
DEMO_USER = {
    "id": "user-1",
    "username": "alice",
    "password": "change-me",
    "role": "editor",
    "tenant": "acme",
}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class PrincipalResponse(BaseModel):
    subject: User
    permissions: list[str]
    token_type: str
    tenant: str
    jti: str | None


class LandingResponse(BaseModel):
    authenticated: bool
    message: str


class Post(BaseModel):
    id: str
    title: str
    author_id: str
    tenant: str
    locked: bool = False


class PostUpdate(BaseModel):
    title: str


POSTS = {
    "post-1": Post(
        id="post-1",
        title="Alice's editable post",
        author_id="user-1",
        tenant="acme",
    ),
    "post-2": Post(
        id="post-2",
        title="Another user's post",
        author_id="user-2",
        tenant="acme",
    ),
    "post-3": Post(
        id="post-3",
        title="Alice's locked post",
        author_id="user-1",
        tenant="acme",
        locked=True,
    ),
}


def get_post(post_id: str) -> Post:
    post = POSTS.get(post_id)
    if post is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found.",
        )
    return post


def post_context(
    request: Request,
    principal: Principal[User],
) -> AuthorizationContext:
    post = get_post(request.path_params["post_id"])
    return AuthorizationContext(
        resource=post,
        request={"method": request.method},
        attributes={"tenant": post.tenant},
    )


@app.get("/")
def index() -> dict[str, str]:
    return {"message": "This route is public."}


@app.get("/landing", response_model=LandingResponse)
def landing(
    principal: Annotated[
        Principal[User] | None,
        Depends(auth.optional),
    ],
) -> LandingResponse:
    if principal is None:
        return LandingResponse(
            authenticated=False,
            message="Hello, guest.",
        )
    return LandingResponse(
        authenticated=True,
        message=f"Hello, {principal.subject.username}.",
    )


@app.post("/token", response_model=TokenResponse)
def create_token(credentials: LoginRequest) -> TokenResponse:
    username_matches = compare_digest(
        credentials.username.encode("utf-8"),
        DEMO_USER["username"].encode("utf-8"),
    )
    password_matches = compare_digest(
        credentials.password.encode("utf-8"),
        DEMO_USER["password"].encode("utf-8"),
    )
    if not username_matches or not password_matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = User(
        id=DEMO_USER["id"],
        username=DEMO_USER["username"],
        role=DEMO_USER["role"],
    )
    expires_in = 15 * 60
    token = jam.issue(
        subject=user,
        via="jwt",
        exp=expires_in,
        jti=token_urlsafe(16),
        permissions=[
            "profile:read",
            "post:read",
            "post:edit",
        ],
        tenant=DEMO_USER["tenant"],
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
    )


@app.get("/me", response_model=PrincipalResponse)
def read_current_user(
    principal: Annotated[
        Principal[User],
        Depends(auth.require("profile:read")),
    ],
) -> PrincipalResponse:
    return PrincipalResponse(
        subject=principal.subject,
        permissions=sorted(principal.permissions),
        token_type=principal.token_type,
        tenant=principal.claims["tenant"],
        jti=principal.jti,
    )


@app.get("/posts/{post_id}", response_model=Post)
def read_post(
    post_id: str,
    principal: Annotated[
        Principal[User],
        Depends(auth.require("post:read")),
    ],
) -> Post:
    return get_post(post_id)


@app.patch("/posts/{post_id}", response_model=Post)
def edit_post(
    post_id: str,
    update: PostUpdate,
    principal: Annotated[
        Principal[User],
        Depends(auth.require("post:edit", context=post_context)),
    ],
) -> Post:
    post = get_post(post_id)
    post.title = update.title
    return post
```

## How the identity model works

### Subject: who can authenticate

```python
@dataclass
class User(BaseSubject):
    id: str
    username: str
    role: str
```

A `Subject` is an application identity. Subject classes must be dataclasses,
inherit from `BaseSubject`, and declare an `id`.

Passing `subject=User` to `Jam` tells it to restore authenticated token data
as a typed `User` rather than a dictionary:

```python
jam = Jam(config="config.toml", subject=User)
```

The password is deliberately not part of `User`. Subject fields are written
to the JWT and a signed JWT is readable by its holder, even though it cannot
be modified without invalidating the signature.

### Principal: who did authenticate

After the JWT is verified, Jam returns `Principal[User]`. It combines:

| Property | Value in this example |
| --- | --- |
| `subject` | The typed `User` reconstructed from token data. |
| `claims` | All JWT claims, including `tenant`, `exp`, and permissions. |
| `permissions` | A normalized `frozenset` of credential grants. |
| `token_type` | `"jwt"`. |
| `jti` | The unique token ID supplied during issuance. |
| `constraints` | Mandatory credential restrictions; empty for this JWT. |

Route code should use this verified `Principal`, not decode the bearer token
itself.

## How token issuance works

```python
token = jam.issue(
    subject=user,
    via="jwt",
    exp=15 * 60,
    jti=token_urlsafe(16),
    permissions=[
        "profile:read",
        "post:read",
        "post:edit",
    ],
    tenant="acme",
)
```

This call demonstrates several credential fields:

- `subject` supplies identity data; Jam moves its `id` into the standard `sub`
  claim;
- `via="jwt"` selects the configured JWT module;
- `exp` sets a lifetime in seconds;
- `jti` assigns a unique identifier that can be used for auditing or token
  revocation;
- `permissions` declares the maximum authority granted to this credential;
- `tenant` is an application-specific claim available from
  `principal.claims`.

Authentication and token issuance are separate operations. Jam creates and
validates credentials, while the application remains responsible for checking
the username and password.

## Authentication dependencies

### Optional authentication

```python
principal: Annotated[
    Principal[User] | None,
    Depends(auth.optional),
]
```

`auth.optional` returns a principal for a valid bearer token and `None` when
no valid credential is available. This is useful for pages that work for both
guests and signed-in users.

### Required authentication and permissions

```python
principal: Annotated[
    Principal[User],
    Depends(auth.require("profile:read")),
]
```

`auth.require("profile:read")` performs authentication and authorization.
FastAPI returns:

- HTTP `401` when the bearer token is missing or invalid;
- HTTP `403` when the token is valid but authorization is denied.

The token must grant the requested permission. Exact names, namespace
wildcards such as `post:*`, and the global `*` wildcard are supported.

## Server-side authorization policy

Credential permissions define what a token may request. Server-side policy
can restrict those grants further:

```python
{
    "effect": "allow",
    "permissions": ["post:edit"],
    "when": {
        "all": [
            {
                "field": "token.tenant",
                "operator": "eq",
                "value": "@context.attributes.tenant",
            },
            {
                "field": "context.resource.author_id",
                "operator": "eq",
                "value": "@subject.id",
            },
        ]
    },
}
```

The two allow rules in `config.toml` first require the token tenant to match
the resource tenant. One then permits the resource owner and the other permits
an administrator. Matching allow rules use OR semantics. Values beginning with
`@` are field references:
`@subject.id` reads the authenticated user's ID, while
`@context.attributes.tenant` reads request-specific context.

The second rule explicitly denies edits to locked posts:

```python
{
    "effect": "deny",
    "permissions": ["post:edit"],
    "when": {
        "field": "context.resource.locked",
        "operator": "eq",
        "value": True,
    },
}
```

Deny rules take precedence. Even an administrator with `post:edit` cannot edit
a locked post under this policy.

Policy cannot add authority absent from an explicit token permission. Both
checks must therefore pass:

1. the JWT grants `post:edit`;
2. an allow rule matches and no deny rule matches.

## Dynamic authorization context

The policy needs the current post, which cannot be known when Jam starts.
`post_context` builds an `AuthorizationContext` for each request:

```python
def post_context(
    request: Request,
    principal: Principal[User],
) -> AuthorizationContext:
    post = get_post(request.path_params["post_id"])
    return AuthorizationContext(
        resource=post,
        request={"method": request.method},
        attributes={"tenant": post.tenant},
    )
```

The context can carry:

- `resource`: the object being accessed;
- `request`: selected request information;
- `attributes`: other application-specific authorization inputs;
- `now`: the current UTC time, added automatically.

Passing a small request dictionary instead of the entire request keeps policy
inputs explicit. Never place secrets in policy context.

## Run the application

Start Uvicorn from the directory containing `app.py`:

```bash
uvicorn app:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) to use FastAPI's
interactive API documentation.

### Try optional authentication

Without a token, the landing route treats the caller as a guest:

```bash
curl http://127.0.0.1:8000/landing
```

```json
{
  "authenticated": false,
  "message": "Hello, guest."
}
```

### Request a token

```bash
curl \
  --request POST \
  --header "Content-Type: application/json" \
  --data '{"username":"alice","password":"change-me"}' \
  http://127.0.0.1:8000/token
```

The response contains a short-lived bearer token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

For the commands below, replace `<access_token>` with that value:

```bash
export ACCESS_TOKEN="<access_token>"
```

### Inspect the principal

```bash
curl \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/me
```

The response shows the typed subject and credential metadata:

```json
{
  "subject": {
    "id": "user-1",
    "username": "alice",
    "role": "editor"
  },
  "permissions": [
    "post:edit",
    "post:read",
    "profile:read"
  ],
  "token_type": "jwt",
  "tenant": "acme",
  "jti": "a-unique-token-id"
}
```

The same token also personalizes the optional route:

```bash
curl \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/landing
```

### Exercise the policy

Alice owns `post-1`, so this request succeeds:

```bash
curl \
  --request PATCH \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"title":"Updated by Alice"}' \
  http://127.0.0.1:8000/posts/post-1
```

Alice does not own `post-2`, so the same permission is denied with HTTP `403`:

```bash
curl \
  --request PATCH \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"title":"Unauthorized update"}' \
  http://127.0.0.1:8000/posts/post-2
```

Alice owns `post-3`, but the deny rule still prevents editing the locked post:

```bash
curl \
  --request PATCH \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"title":"Cannot update a locked post"}' \
  http://127.0.0.1:8000/posts/post-3
```

Both denied requests return:

```json
{
  "detail": "Permission denied."
}
```

## Before using this in production

The example intentionally leaves out application-specific infrastructure.
For a production service:

- load users and resources from a database;
- hash passwords with Argon2id or another password hashing algorithm;
- keep signing keys in a secret manager and define a rotation procedure;
- use HTTPS so credentials and tokens are encrypted in transit;
- choose a suitable token lifetime and implement revocation or refresh tokens
  when the threat model requires them;
- use stable permission names and review grants at token issuance;
- treat token claims as snapshots and avoid embedding rapidly changing
  authorization state;
- consider `RS256` when services should verify tokens without receiving the
  private signing key;
- restrict CORS origins and rate-limit the login endpoint;
- log authorization decisions without logging raw credentials or secrets.
