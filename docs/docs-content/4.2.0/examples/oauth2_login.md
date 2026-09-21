# OAuth2 login

This FastAPI example redirects a user to GitHub, exchanges the authorization
code through Jam, reads the GitHub profile, and creates a short-lived local
JWT. The provider access token never becomes the application's login cookie.

## Register and configure the OAuth application

Create a GitHub OAuth App with this callback URL:

```text
http://127.0.0.1:8000/oauth/github/callback
```

Install the dependencies and export the credentials:

```bash
pip install fastapi "jamlib[fastapi]" httpx uvicorn

export GITHUB_CLIENT_ID="..."
export GITHUB_CLIENT_SECRET="..."
export JWT_SECRET_KEY="$(python -c \
  'from jam.utils import generate_symmetric_key; print(generate_symmetric_key())')"
```

Create `config.toml`:

```toml
[jam.oauth2.github]
client_id = "$GITHUB_CLIENT_ID"
client_secret = "$GITHUB_CLIENT_SECRET"
redirect_url = "http://127.0.0.1:8000/oauth/github/callback"

[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"
```

The name `github` selects Jam's built-in GitHub endpoints. A custom provider
also supplies `auth_url` and `token_url`.

!!! tip "Other configuration formats"
    `Jam` accepts a Python dictionary or TOML, YAML, and JSON files. Keep
    OAuth client secrets in environment variables or a secret manager.

## Create the application

Create `app.py`:

```python
from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from jam import BaseSubject, Jam
from jam.authz import Principal
from jam.ext.fastapi import CredentialSource, JamAuth


@dataclass
class User(BaseSubject):
    id: str
    username: str


jam = Jam(config="config.toml", subject=User)
github = jam.oauth2["github"]
auth = JamAuth(
    jam,
    via="jwt",
    sources=[CredentialSource.cookie("access_token")],
)
app = FastAPI(title="Jam OAuth2 login example")

# Use a shared, expiring server-side store in production.
PENDING_STATES: set[str] = set()


class UserResponse(BaseModel):
    id: str
    username: str


@app.get("/login/github")
def start_github_login() -> RedirectResponse:
    state = token_urlsafe(32)
    PENDING_STATES.add(state)
    authorization_url = github.get_authorization_url(
        scope=["read:user"],
        state=state,
    )
    return RedirectResponse(authorization_url)


@app.get("/oauth/github/callback")
def github_callback(code: str, state: str) -> RedirectResponse:
    if state not in PENDING_STATES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state.",
        )
    PENDING_STATES.remove(state)

    provider_tokens = github.fetch_token(code=code)
    provider_access_token = provider_tokens.get("access_token")
    if not isinstance(provider_access_token, str):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="OAuth provider returned no access token.",
        )

    profile_response = httpx.get(
        "https://api.github.com/user",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {provider_access_token}",
        },
        timeout=10,
    )
    profile_response.raise_for_status()
    profile = profile_response.json()

    local_token = jam.issue(
        User(
            id=str(profile["id"]),
            username=profile["login"],
        ),
        via="jwt",
        exp=15 * 60,
        jti=token_urlsafe(16),
        permissions=["profile:read"],
        identity_provider="github",
    )

    response = RedirectResponse("/me", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        "access_token",
        local_token,
        max_age=15 * 60,
        httponly=True,
        secure=False,  # Use True behind HTTPS.
        samesite="lax",
    )
    return response


@app.get("/me", response_model=UserResponse)
def me(
    principal: Annotated[
        Principal[User],
        Depends(auth.require("profile:read")),
    ],
) -> UserResponse:
    return UserResponse(
        id=principal.subject.id,
        username=principal.subject.username,
    )
```

## Understand the trust boundaries

`state` binds the callback to a login initiated by this application and must
be unpredictable, single-use, and short-lived. The in-memory set is suitable
only for a one-process demonstration; use a shared server-side session store
in production.

The authorization code is exchanged by `github.fetch_token()`. The resulting
GitHub access token authorizes GitHub API calls—it is not automatically proof
of a local application identity. The application fetches a profile, maps the
provider ID to a local user, and only then issues its own Jam credential.

## Run the flow

```bash
uvicorn app:app --reload
```

Open [http://127.0.0.1:8000/login/github](http://127.0.0.1:8000/login/github).
After GitHub authorization, the callback sets the local cookie and redirects
to `/me`.

In production, use HTTPS and `Secure` cookies, persist provider-to-user
mappings, define account-linking rules, handle provider errors without leaking
tokens, request the minimum scopes, and never log authorization codes, access
tokens, refresh tokens, or client secrets.
