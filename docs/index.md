---
title: Home
image: assets/logo_n_title.png
---
<div style="text-align: center;">
    <img alt="logo" src="assets/loog_n_title.png" />
    <p>Welcome to Jam documentation!</p>
</div>

![Python Version](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
[![PyPI - Version](https://img.shields.io/pypi/v/jamlib)](https://pypi.org/project/jamlib/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/jamlib?period=total&units=INTERNATIONAL_SYSTEM&left_color=GRAY&right_color=RED&left_text=Downloads)](https://pypi.org/project/jamlib/)
![tests](https://github.com/mkrdnk/jam/actions/workflows/run-tests.yml/badge.svg)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/mkrdnk/jam)
[![GitHub License](https://img.shields.io/github/license/mkrdnk/jam)](https://github.com/mkrdnk/jam/blob/master/LICENSE.md)

## About
**Jam (Jam Auth Module)** - A universal auth* combine that provides popular auth mechanisms strictly according to the specification.

## Installation
<!-- termynal -->
```
> pip install jamlib
---> 100%
Installed!
```


## Quick example

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class User(BaseSubject):
    id: str
    email: str = ""


jam = Jam(config="config.toml", subject=User)

token = jam.issue(User(id="1", email="user@example.com"), via="jwt")
principal = jam.authenticate(token, via="jwt")
user = principal.subject
```

See the [Quickstart](/usage/quickstart) for a step-by-step walkthrough.

## Asynchronous support
!!! note
    The async facade is available in the `jam.aio` module. The methods are
    awaitable versions of the historical sync API (`jwt_encode`,
    `session_create`, `otp_code`, ...).

```python
from jam.aio import Jam

jam = Jam(config="config.toml")
token = await jam.jwt_encode(
    iss="Jam",
    sub="username@example.com"
)
```


## Why Jam?
Jam is a library that provides the most popular AUTH* mechanisms right out of the box.

* [JOSE](usage/jose/)
* [PASETO](usage/paseto.md)
* [Server side sessions](usage/sessions.md)
* [OTP](usage/otp.md)
* [OAuth2](usage/oauth2.md)
* [SAML](usage/saml.md)


### Framework integrations

Jam provides ready-to-use integrations for the most popular frameworks:

* [FastAPI](framework_integrations/fastapi.md)
* [Starlette](framework_integrations/starlette.md)
* [Litestar](framework_integrations/litestar.md)
* [Flask](framework_integrations/flask.md)

Each integration offers built-in middleware or plugin support for JWT and session-based authentication.

### Why choose Jam?
Jam supports many authentication methods out of the box with minimal dependencies.
Here is a comparison with other libraries:

| Features / Library    | **Jam** | [Authx](https://authx.yezz.me/) | [PyJWT](https://pyjwt.readthedocs.io) | [AuthLib](https://docs.authlib.org) | [OTP Auth](https://otp.authlib.org/) |
|-----------------------|--------|----------------------------------|---------------------------------------|-------------------------------------|--------------------------------------|
| JOSE                  | ✅     | ❌ only JWT                      | ❌ only JWT                           | ✅                                  | ❌                                   |
| JWT black/white lists | ✅     | ❌                               | ❌                                    | ❌                                  | ❌                                   |
| PASETO                | ✅     | ❌                               | ❌                                    | ❌                                  | ❌                                   |
| Server side sessions  | ✅     | ✅                               | ❌                                    | ❌                                  | ❌                                   |
| OTP                   | ✅     | ❌                               | ❌                                    | ❌                                  | ✅                                   |
| OAuth2                | ✅     | ✅                               | ❌                                    | ✅                                  | ❌                                   |
| SAML 2.0              | ✅     | ❌                               | ❌                                    | ❌                                  | ❌                                   |
| Flexible config       | ✅     | ❌                               | ❌                                    | ❌                                  | ❌                                   |
| Modularity            | ✅     | ❌                               | ❌                                    | ❌                                  | ❌                                   |
