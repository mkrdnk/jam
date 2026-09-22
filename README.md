# Jam

![Jam](https://github.com/mkrdnk/jam/blob/master/docs/public/assets/h_logo_n_title.png?raw=true)

![Python Version](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
[![PyPI Version](https://img.shields.io/pypi/v/jamlib)](https://pypi.org/project/jamlib/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/jamlib?period=total&units=INTERNATIONAL_SYSTEM&left_color=GRAY&right_color=RED&left_text=Downloads)](https://pypi.org/project/jamlib/)
[![Tests](https://github.com/mkrdnk/jam/actions/workflows/run-tests.yml/badge.svg)](https://github.com/mkrdnk/jam/actions/workflows/run-tests.yml)
[![License](https://img.shields.io/github/license/mkrdnk/jam)](https://github.com/mkrdnk/jam/blob/master/LICENSE.md)

**Jam is a typed, modular authentication and authorization framework for
Python.** It brings tokens, delegated credentials, sessions, identity
protocols, and policy enforcement behind one consistent API without forcing
applications into a particular web framework.

Use the high-level `Jam` or `AsyncJam` facade for complete authentication
flows, or use the JOSE, PASETO, Macaroon, SAML, OTP, session, and OAuth2
modules independently.

- [Documentation](https://jam.makridenko.com)
- [Quickstart](https://jam.makridenko.com/latest/gettingstarted/quickstart)
- [Changelog](https://github.com/mkrdnk/jam/blob/master/CHANGELOG.md)
- [Security policy](https://github.com/mkrdnk/jam/blob/master/SECURITY.md)

## What Jam provides

| Area | Capabilities |
| --- | --- |
| Credentials | JWT, JWS, JWE, PASETO v1-v4, Macaroons, and SAML 2.0 |
| Stateful authentication | Sessions and shared credential token lists |
| Identity and verification | OAuth2 clients, HOTP, and TOTP |
| Authorization | Typed principals, credential constraints, contextual policy rules, and deny-by-default evaluation |
| Key management | In-memory and file-backed keychains, rotation, historical-key verification, and revocation |
| Integrations | Django, Django REST Framework, Django Modern REST, FastAPI, Starlette, Litestar, and Flask |
| Configuration | Python dictionaries, TOML, YAML, and JSON with environment-variable substitution |
| Runtime model | Synchronous and asynchronous facades with native async I/O backends |

Jam keeps optional features optional. The core package depends only on
`cryptography`; integrations and storage clients are installed through
extras when needed.

## Installation

Jam requires Python 3.10 or newer.

```bash
pip install jamlib
```

Install only the optional dependencies your application uses:

```bash
pip install "jamlib[redis]"    # Redis sessions and token lists
pip install "jamlib[oauth2]"   # OAuth2 HTTP clients
pip install "jamlib[yaml]"     # YAML configuration
pip install "jamlib[fastapi]"  # FastAPI integration
pip install "jamlib[django]"   # Django integration
pip install "jamlib[drf]"      # Django REST Framework integration
```

Other extras include `cli`, `json`, `toml`, `starlette`, `litestar`, `flask`,
and `dmr`.

## Quickstart

Create a minimal `config.toml`:

```toml
[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[jam.authz.rules]
"profile:read" = ["*"]
"post:create" = ["is_authenticated"]
```

Set a sufficiently strong secret outside the configuration file:

```bash
export JWT_SECRET_KEY="replace-with-at-least-32-random-characters"
```

Define the application subject and use the issue-authenticate-authorize flow:

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class User(BaseSubject):
    id: str
    email: str
    is_authenticated: bool = True


jam = Jam(config="config.toml", subject=User)
user = User(id="1", email="user@example.com")

token = jam.issue(
    user,
    via="jwt",
    exp=3600,
    permissions=["profile:read", "post:create"],
)

principal = jam.authenticate(token, via="jwt")

assert principal.subject == user
assert jam.authorize(principal, "post:create")
assert not jam.authorize(principal, "post:delete")
```

Authentication returns a `Principal`: the verified subject, registered and
application claims, permissions, credential type, and any constraints carried
by the credential. Authorization evaluates credential constraints before
server-side policy, so a policy cannot widen authority granted by a token or
Macaroon.

## One facade, multiple credential types

The facade selects a configured mechanism through `via`:

```python
jwt = jam.issue(user, via="jwt", permissions=["profile:read"])
paseto = jam.issue(user, via="paseto", permissions=["profile:read"])
macaroon = jam.issue(user, via="macaroon", permissions=["profile:read"])
saml_response = jam.issue(user, via="saml")

principal = jam.authenticate(jwt, via="jwt")
```

Modules are also available directly when lower-level protocol control is
needed:

```python
decoded = jam.macaroon.decode(macaroon)
attenuated = decoded.add_caveat(b"permission = profile:read")

header_and_payload = jam.jwt.decode(jwt)
```

Only configured modules are available. Accessing a missing module fails with a
`JamConfigurationError` instead of an untyped `None` attribute error.

## Asynchronous applications

`AsyncJam` provides native async session, token-list, and OAuth2 operations.
Cryptography, OTP, Macaroon processing, and authorization remain synchronous
because they do not cross an I/O boundary.

```python
from jam.aio import AsyncJam


jam = AsyncJam(config="config.toml", subject=User)

token = await jam.issue(user, via="jwt", exp=3600)
principal = await jam.authenticate(token, via="jwt")

allowed = jam.authorize(principal, "profile:read")

await jam.aclose()
```

`AsyncJam` can also be used as an async context manager when it owns I/O
clients:

```python
async with AsyncJam(config="config.toml", subject=User) as jam:
    token = await jam.issue(user, via="session")
```

## Authorization that credentials cannot bypass

Jam separates identity, credential authority, and application policy:

1. `authenticate()` verifies the credential and creates a `Principal`.
2. Credential constraints are evaluated first.
3. The configured server-side policy evaluates the requested permission and
   context.
4. Any failed constraint or policy rule denies access.

```python
from jam.authz import AuthorizationContext


context = AuthorizationContext(
    request=request,
    resource=article,
)

if not jam.authorize(principal, "article:update", context):
    raise PermissionError
```

Macaroon caveats, token permissions, time restrictions, and resource-aware
policy checks can only reduce authority; they cannot silently grant permissions
that the credential did not carry.

## Framework integrations

Jam integrations are deliberately thin: they extract credentials, delegate to
`Jam` or `AsyncJam`, and expose the resulting principal to the framework.

- [Django](https://jam.makridenko.com/latest/integrations/django/django)
- [Django REST Framework](https://jam.makridenko.com/latest/integrations/django/drf)
- [Django Modern REST](https://jam.makridenko.com/latest/integrations/django/dmr)
- [FastAPI](https://jam.makridenko.com/latest/integrations/fastapi)
- [Starlette](https://jam.makridenko.com/latest/integrations/starlette)
- [Litestar](https://jam.makridenko.com/latest/integrations/litestar)
- [Flask](https://jam.makridenko.com/latest/integrations/flask)

## Standalone modules

The facade is optional. Protocol implementations can be constructed directly:

```python
from jam.jose import JWT
from jam.paseto import PASETOv4


jwt = JWT(alg="HS256", secret_key="replace-with-a-strong-secret")
paseto = PASETOv4(purpose="local", secret_key=b"\x00" * 32)
```

See the documentation for:

- [JOSE](https://jam.makridenko.com/latest/authx/jose/index)
- [PASETO](https://jam.makridenko.com/latest/authx/paseto)
- [Macaroons](https://jam.makridenko.com/latest/authx/macaroons)
- [SAML](https://jam.makridenko.com/latest/authx/saml)
- [Sessions](https://jam.makridenko.com/latest/authx/sessions)
- [OAuth2](https://jam.makridenko.com/latest/authx/oauth2)
- [OTP](https://jam.makridenko.com/latest/authx/otp)
- [Authorization](https://jam.makridenko.com/latest/authz/rules)

## Development

```bash
git clone https://github.com/mkrdnk/jam.git
cd jam
uv sync --group tests --all-extras
uv run pytest -x
```

Jam is licensed under the
[Apache License 2.0](https://github.com/mkrdnk/jam/blob/master/LICENSE.md).
