# Jam

![logo](https://github.com/mkrdnk/jam/blob/master/docs/assets/h_logo_n_title.png?raw=true)

![Python Version](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
[![PyPI - Version](https://img.shields.io/pypi/v/jamlib)](https://pypi.org/project/jamlib/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/jamlib?period=total&units=INTERNATIONAL_SYSTEM&left_color=GRAY&right_color=RED&left_text=Downloads)](https://pypi.org/project/jamlib/)
![tests](https://github.com/mkrdnk/jam/actions/workflows/run-tests.yml/badge.svg)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/mkrdnk/jam)
[![GitHub License](https://img.shields.io/github/license/mkrdnk/jam)](https://github.com/mkrdnk/jam/blob/master/LICENSE.md)

**Jam (Jam Auth Module)** - A universal auth* combine that provides popular auth mechanisms strictly according to the specification.

* Documentation: [jam.makridenko.ru](https://jam.makridenko.ru)
* Changelog: [CHANGELOG.md](https://github.com/mkrdnk/jam/blob/master/CHANGELOG.md)


## Install
```bash
pip install jamlib
```

## Quick example
```python
from jam import Jam

jam = Jam(config="config.toml")

jwt = jam.jwt_encode(payload={"user": 1})
session_id = jam.session_create(session_key="username", data={"user": 1})
otp_code = jam.otp_code(secret="3DB7FOAOFBCI3WFDRE7EPF43CA")
```

## Why Jam?
Jam is a library that provides the most popular AUTH* mechanisms right out of the box.

* [JOSE](https://jam.makridenko.ru/usage/jose/)
* [PASETO](https://jam.makridenko.ru/usage/paseto/)
* [Server side sessions](https://jam.makridenko.ru/usage/sessions/)
* [OTP](https://jam.makridenko.ru/usage/otp/)
* [OAuth2](https://jam.makridenko.ru/usage/oauth2/)
* [SAML](https://jam.makridenko.ru/usage/saml/)

### Framework integrations

Jam provides ready-to-use integrations for the most popular frameworks:

* [FastAPI](https://jam.makridenko.ru/framework_integrations/fastapi)
* [Starlette](https://jam.makridenko.ru/framework_integrations/starlette)
* [Litestar](https://jam.makridenko.ru/framework_integrations/litestar)
* [Flask](https://jam.makridenko.ru/framework_integrations/flask)

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
