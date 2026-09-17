# Jam

![logo](https://github.com/mkrdnk/jam/blob/master/docs/public/assets/h_logo_n_title.png?raw=true)

![Python Version](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
[![PyPI - Version](https://img.shields.io/pypi/v/jamlib)](https://pypi.org/project/jamlib/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/jamlib?period=total&units=INTERNATIONAL_SYSTEM&left_color=GRAY&right_color=RED&left_text=Downloads)](https://pypi.org/project/jamlib/)
![tests](https://github.com/mkrdnk/jam/actions/workflows/run-tests.yml/badge.svg)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/mkrdnk/jam)
[![GitHub License](https://img.shields.io/github/license/mkrdnk/jam)](https://github.com/mkrdnk/jam/blob/master/LICENSE.md)

**Jam (Jam Auth Module)** - Jam (Jam Auth Module) - A universal auth* framework that provides popular auth mechanisms strictly according to the specification.

* Documentation: [jam.makridenko.ru](https://jam.makridenko.ru)
* Changelog: [CHANGELOG.md](https://github.com/mkrdnk/jam/blob/master/CHANGELOG.md)


## Install
```bash
pip install jamlib
```

## Quick example
```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class User(BaseSubject):
    id: int
    email: str


jam = Jam(config="config.toml", subject=User)

user = User(id=1, email="user@example.com")

token = jam.issue(subject=user, via="jwt")
principal = jam.authenticate(token, via="jwt")
user = principal.subject

allowed: bool = jam.authorize(
    principal=principal,
    permission="post:create"
)
```

## Why Jam?
Jam is a library that provides the most popular AUTH* mechanisms right out of the box.

* [JOSE](https://jam.makridenko.ru/4.1.0/authentication/jose/index)
* [PASETO](https://jam.makridenko.ru/4.1.0/authentication/paseto)
* [Server side sessions](https://jam.makridenko.ru/4.1.0/authentication/sessions/)
* [OTP](https://jam.makridenko.ru/4.1.0/authentication/otp/)
* [OAuth2](https://jam.makridenko.ru/4.1.0/identity/oauth2/)
* [SAML](https://jam.makridenko.ru/4.1.0/authentication/saml/)

### Authorization
Jam combines permissions granted to one credential with server-side policy rules. This makes it possible to issue two tokens for the same user with different permissions and to restrict those permissions using the current time, resource or request.

```python
principal = jam.authenticate(token, via="jwt")

if jam.authorize(principal, "user:delete"):
    ...
```

### Framework integrations

Jam provides ready-to-use integrations for the most popular frameworks:

* [Django](https://jam.makridenko.ru/4.1.0/integrations/django)
* [Django REST Framework](https://jam.makridenko.ru/4.1.0/integrations/django/drf)
* [FastAPI](https://jam.makridenko.ru/4.1.0/integrations/fastapi)
* [Starlette](https://jam.makridenko.ru/4.1.0/integrations/starlette)
* [Litestar](https://jam.makridenko.ru/4.1.0/integrations/litestar)
* [Flask](https://jam.makridenko.ru/4.1.0/integrations/flask)

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
