# FastAPI application with JWT

This example builds a small FastAPI application that:

1. accepts a username and password;
2. issues a short-lived JWT;
3. reads the JWT from the `Authorization` header;
4. verifies the token before returning protected user data.

The application uses an in-memory user to keep the example focused on Jam.
The final section explains what must change before using this pattern in
production.

## Install the dependencies

Create a new directory and virtual environment:

```bash
mkdir fastapi-jwt-example
cd fastapi-jwt-example

python -m venv .venv
source .venv/bin/activate
```

Install Jam with its FastAPI integration and an ASGI server:

```bash
pip install fastapi "jamlib[fastapi]" uvicorn
```

## Configure the signing secret

This example signs tokens with `HS256`. Both token creation and verification
use the same secret. Generate a random secret and expose it through the
environment:

```bash
export JWT_SECRET_KEY="$(python -c \
  'import secrets; print(secrets.token_urlsafe(32))')"
```

Keep the same secret between application restarts if existing tokens must
remain valid. In production, load it from a secret manager instead of source
control.

Or you can use [Jam CLI](/latest/dev/cli):

```bash
jam keys symmetric
```

## Create the application

Create `app.py`:

```python
import os
from secrets import compare_digest
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

from jam import Jam
from jam.authz import Principal
from jam.ext.fastapi import JamAuth


JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY must be set")


jam = Jam(
    config={
        "jose": {
            "jwt": {
                "alg": "HS256",
                "secret_key": JWT_SECRET_KEY,
            }
        }
    }
)
auth = JamAuth(jam, via="jwt")
app = FastAPI(title="Jam JWT example")


# This is only a demonstration. A real application loads the user from a
# database and stores a password hash, never the plaintext password.
DEMO_USER = {
    "id": "user-1",
    "username": "alice",
    "password": "change-me",
}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class UserResponse(BaseModel):
    id: str
    username: str


@app.get("/")
def index() -> dict[str, str]:
    return {"message": "This route is public."}


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

    expires_in = 15 * 60
    token = jam.issue(
        {
            "id": DEMO_USER["id"],
            "username": DEMO_USER["username"],
        },
        via="jwt",
        exp=expires_in,
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
    )


@app.get("/me", response_model=UserResponse)
def read_current_user(
    principal: Annotated[Principal, Depends(auth)],
) -> UserResponse:
    return UserResponse(
        id=principal.subject["id"],
        username=principal.subject["username"],
    )
```

## How it works

### Configure Jam

```python
jam = Jam(
    config={
        "jose": {
            "jwt": {
                "alg": "HS256",
                "secret_key": JWT_SECRET_KEY,
            }
        }
    }
)
```

The `jose.jwt` section enables Jam's JWT module. `HS256` creates a signed JWT:
clients can read its payload, but they cannot change it without invalidating
the signature. A signed JWT is not encrypted, so never place passwords,
secrets, or other sensitive data in its payload.

### Issue a token

```python
token = jam.issue(
    {"id": "user-1", "username": "alice"},
    via="jwt",
    exp=15 * 60,
)
```

`via="jwt"` selects the configured JWT module. Jam stores the subject ID in
the standard JWT `sub` claim and adds an `exp` claim 15 minutes in the future.
The remaining subject fields become token payload fields.

Authentication and token issuance are separate operations. Jam creates and
validates credentials, while your application remains responsible for
checking the username and password.

### Protect a route

```python
auth = JamAuth(jam, via="jwt")


@app.get("/me")
def read_current_user(
    principal: Annotated[Principal, Depends(auth)],
):
    return principal.subject
```

`JamAuth` is a FastAPI dependency. For each request it:

1. looks for `Authorization: Bearer <token>`;
2. asks Jam to verify the signature and registered claims such as `exp`;
3. converts the verified payload into a `Principal`;
4. returns HTTP `401` if the header is missing or the token is invalid.

The `Principal` contains the authenticated `subject`, all token `claims`, and
the credential `token_type`. Route code should use data from this verified
object rather than decoding the bearer token itself.

## Run the application

Start Uvicorn from the directory containing `app.py`:

```bash
uvicorn app:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) to use FastAPI's
interactive API documentation.

The public route works without a token:

```bash
curl http://127.0.0.1:8000/
```

Request a token with the example credentials:

```bash
curl \
  --request POST \
  --header "Content-Type: application/json" \
  --data '{"username":"alice","password":"change-me"}' \
  http://127.0.0.1:8000/token
```

The response contains a bearer token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

Copy `access_token` into the protected request:

```bash
curl \
  --header "Authorization: Bearer <access_token>" \
  http://127.0.0.1:8000/me
```

The verified user is returned:

```json
{
  "id": "user-1",
  "username": "alice"
}
```

A missing, expired, modified, or incorrectly signed token produces HTTP
`401 Unauthorized`.

## Before using this in production

The example intentionally leaves out application-specific infrastructure.
For a production service:

- load users from a database;
- hash passwords with a password hashing algorithm such as Argon2id, and
  compare password hashes instead of storing plaintext passwords;
- keep signing keys in a secret manager and define a rotation procedure;
- use HTTPS so credentials and tokens are encrypted in transit;
- choose a suitable token lifetime and implement revocation or refresh tokens
  when your threat model requires them;
- consider an asymmetric algorithm such as `RS256` when services should verify
  tokens without receiving the private signing key;
- restrict CORS origins and add rate limiting to the login endpoint.
