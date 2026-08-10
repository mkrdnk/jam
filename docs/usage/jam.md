---
title: Jam instance
---

`Jam` is the main facade of the library. It loads modules from the
[configuration](/configuration) and exposes three high-level operations:
`issue`, `authenticate` and `authorize`.

Module-level classes (e.g. `jam.jose.JWT`, `jam.paseto.PASETOv4`) remain
fully usable standalone. `Jam` is a convenience layer on top of them.

## Creating an instance

Class: `jam.Jam`

Args:

* `config`: `str | dict[str, Any] | None = None` - Configuration dict or
  config file path (TOML/YAML/JSON). See [Configuration](/configuration).
* `pointer`: `str = "jam"` - Config pointer.
* `serializer`: `BaseEncoder | type[BaseEncoder] = JsonEncoder` - JSON
  serializer used by token modules.
* `subject`: `type[BaseSubject] | None = None` - Subject class override.
  Used by `authenticate` to build typed subjects.
* `plugins`: `list[type[BasePlugin]] | None = None` - List of plugins.

```python
from jam import Jam

jam = Jam(config="config.toml")
```

## Attributes

After initialization the configured modules are available as attributes:

| Attribute | Type | Configured by |
|-----------|------|---------------|
| `jam.jwt` | `jam.jose.JWT` | `[jam.jose.jwt]` |
| `jam.jws` | `jam.jose.JWS` | `[jam.jose.jws]` |
| `jam.jwe` | `jam.jose.JWE` | `[jam.jose.jwe]` |
| `jam.jose` | `dict[str, Any]` | `[jam.jose]` |
| `jam.session` | `RedisSessions` / `JSONSessions` | `[jam.session]` |
| `jam.paseto` | `PASETOv1`–`PASETOv4` | `[jam.paseto]` |
| `jam.otp` | `HOTP` / `TOTP` class | `[jam.otp]` |
| `jam.oauth2` | `dict[str, OAuth2Client]` | `[jam.oauth2]` |
| `jam.config` | `dict[str, Any] | None` | - |
| `jam.subject` | `type[BaseSubject]` | `subject=` argument |

Unconfigured modules remain `None`. You can always access the underlying
module directly, e.g. `jam.jwt.encode(payload={...})`.

## issue

Method: `jam.issue`

Issues a token or a session for a subject.

Args:

* `subject`: `BaseSubject | dict[str, Any]` - Subject instance or a dict
  with an `"id"` key. Serialized into the payload; the `id` becomes `sub`.
* `via`: `str | None = None` - Token type: `"jwt"`, `"paseto"`, `"session"`.
  With `None`, auto-detect: JWT first, then PASETO.
* `exp`: `int | None = None` - Expiration in seconds.
* `iss`: `str | None = None` - Issuer.
* `aud`: `str | None = None` - Audience.
* `nbf`: `int | None = None` - Not-before in seconds.
* `jti`: `str | None = None` - Token ID.
* `**claims` - Extra payload claims.

Returns:

`str` - Issued token or session ID.

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class User(BaseSubject):
    id: str
    role: str = "user"


jam = Jam(config="config.toml")

jwt_token = jam.issue(User(id="1", role="admin"), via="jwt", exp=3600)
paseto_token = jam.issue({"id": "1", "role": "admin"}, via="paseto")
session_id = jam.issue(User(id="1"), via="session")
```

## authenticate

Method: `jam.authenticate`

Verifies a token or a session and returns a subject.

Args:

* `token`: `str` - Token or session ID.
* `via`: `str | None = None` - Token type: `"jwt"`, `"jwe"`, `"paseto"`,
  `"session"`. With `None`, the type is detected from the token format:
  `v[1-4].(local|public).` prefix → PASETO, five segments → JWE, three
  segments → JWT, otherwise session.

Returns:

`BaseSubject | dict[str, Any]` - Subject instance when a dataclass subject
is configured, otherwise the raw payload dict.

Raises:

* `JamConfigurationError` - No matching module is configured.
* `JamSessionNotFound` - Session does not exist.

```python
@dataclass
class User(BaseSubject):
    id: str
    role: str = "user"


jam = Jam(config="config.toml", subject=User)

user = jam.authenticate(jwt_token, via="jwt")
print(user.id)   # -> "1"
print(user.role) # -> "admin"
```

## authorize

Method: `jam.authorize`

Checks whether a subject is allowed to perform a permission. Requires the
`[jam.authz]` section in the config. Deny by default.

Args:

* `subject`: `BaseSubject` - Subject instance.
* `permission`: `str` - Permission name, e.g. `"post:edit"`.

Returns:

`bool` - True if allowed, False otherwise.

Raises:

* `JamConfigurationError` - No authz policy is configured.

```python
jam = Jam(config="config.toml")

user = jam.authenticate(token)
if jam.authorize(user, "post:edit"):
    ...
```

See [Authorization](/usage/authz) for the policy syntax.

## Async

The async facade lives in `jam.aio`. It keeps the historical `jwt_encode`,
`session_create`, `otp_code`, etc. methods and returns awaitables:

```python
from jam.aio import Jam

jam = Jam(config="config.toml")
token = await jam.jwt_encode(sub="user@example.com", exp=3600)
```
