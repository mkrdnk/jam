# Configuration

## Config file

The configuration only works for `jam.Jam`/`jam.aio.Jam`.
Standalone modules such as `jam.jose.JWT` and `jam.paseto.PASETOv4` are
configured through their own `__init__` methods. See the documentation for the
module you use.

### Instance

The `Jam` class accepts several parameters:

```python
from jam import Jam
from jam.encoders import JsonEncoder

jam = Jam(
    config="path/to/config.toml",  # a path, a Python dict, or None
    pointer="jam",
    serializer=JsonEncoder,
)
```

#### config: str | dict[str, Any] | None

This is a configuration file path, a dictionary, or `None`. With `None`, Jam
uses an empty configuration unless a subclass defines a class-level `config`.

##### Python dict
```python
import os

from jam import Jam

config = {
    "jose": {
        "jwt": {
            "alg": "HS256",
            "secret_key": os.getenv("JWT_SECRET_KEY")
        }
    },
    "paseto": {
        "version": "v4",
        "purpose": "local",
        "secret_key": os.getenv("PASETO_SECRET_KEY")
    }
}

jam = Jam(config=config)
jwt = jam.issue({"user": 1}, via="jwt")
paseto = jam.issue({"user": 1}, via="paseto")
```

##### TOML
```toml
[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[jam.paseto]
version = "v4"
purpose = "local"
secret_key = "$PASETO_SECRET_KEY"
```
```python
from jam import Jam

jam = Jam(config="config.toml")
jwt = jam.issue({"user": 1}, via="jwt")
paseto = jam.issue({"user": 1}, via="paseto")
```

##### YAML
```yaml
jam:
  jose:
    jwt:
      alg: HS256
      secret_key: $JWT_SECRET_KEY
  paseto:
    version: v4
    purpose: local
    secret_key: $PASETO_SECRET_KEY
```
```python
from jam import Jam

jam = Jam(config="config.yaml")
jwt = jam.issue({"user": 1}, via="jwt")
paseto = jam.issue({"user": 1}, via="paseto")
```

##### Json
```json
{
  "jose": {
    "jwt": {
      "alg": "HS256",
      "secret_key": "$JWT_SECRET_KEY"
    }
  },
  "paseto": {
    "version": "v4",
    "purpose": "local",
    "secret_key": "$PASETO_SECRET_KEY"
  }
}
```
```python
from jam import Jam

jam = Jam(config="config.json")
jwt = jam.issue({"user": 1}, via="jwt")
paseto = jam.issue({"user": 1}, via="paseto")
```

---
#### pointer: str = "jam"
This is the point that Jam will read as config.

For example, if we do it like this:
```python
from jam import Jam

jam = Jam(
    config="config.toml",
    pointer="anotherpointer" # <- Another pointer
)
jwt = jam.issue({"user": 1}, via="jwt")
paseto = jam.issue({"user": 1}, via="paseto")
```

Our config file will look like this:
```toml
[anotherpointer.jose.jwt]  # pointer
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[anotherpointer.paseto]  # pointer
version = "v4"
purpose = "local"
secret_key = "$PASETO_SECRET_KEY"
```

!!! tip
    This can be useful for configuring two instances of `Jam` in a single file, for example.

---

#### serializer: type[BaseEncoder] = JsonEncoder

JSON object serializer. By default, Jam uses `JsonEncoder`, which uses the
Python standard library `json` module.

It can also be passed in the config file as a string:
```toml
[jam]
serializer = "jam.encoders.JsonEncoder"

[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"
```

For more details, see the [documentation on serialization](/4.1.0/dev/serializers).

### Config sections

The config is a dict of sections; each section builds one module (or the
policy). The full list:

| Section | Module | Docs |
|---------|--------|------|
| `jose.jwt` | `jam.jose.JWT` | [JWT](/4.1.0/authx/jose/jwt) |
| `jose.jws` | `jam.jose.JWS` | [JWS](/4.1.0/authx/jose/jws) |
| `jose.jwe` | `jam.jose.JWE` | [JWE](/4.1.0/authx/jose/jwe) |
| `paseto` | `jam.paseto.PASETOv1`–`v4` | [PASETO](/4.1.0/authx/paseto) |
| `session` | `RedisSessions` / `JSONSessions` | [Sessions](/4.1.0/authx/sessions) |
| `otp` | `HOTP` / `TOTP` | [OTP](/4.1.0/authx/otp) |
| `oauth2` | `dict[str, OAuth2Client]` | [OAuth2](/4.1.0/authx/oauth2) |
| `keychains` | `dict[str, BaseKeyChain]` | [KeyChain](/4.1.0/dev/keychain) |
| `authz` | `jam.Policy` (or custom) | [Authorization](/4.1.0/authz/subject) |
| `serializer` | `BaseEncoder` | [Serialization](/4.1.0/dev/serializers) |

Each section is optional — configure only what you use. Modules are then
available as attributes on the instance, e.g. `jam.jwt`, `jam.paseto`.

### Environment variables

TOML, YAML, and JSON configuration files support `$VAR`, `${VAR}`, and
`${VAR:-default}` substitutions. For a Python dict, use `os.getenv`.

Example:

```toml
[jam.jose.jwt]
alg = "$JWT_ALG"
secret_key = "$JWT_SECRET"
```

!!! note
    Some modules read certain environment variables by default, as described in detail in each module.

### Configuration format dependencies

TOML is built into Python 3.11 and later. On Python 3.10, install TOML
support:

```bash
pip install "jamlib[toml]"
```

YAML configuration requires:

```bash
pip install "jamlib[yaml]"
```

### Config pointer

The `pointer` argument selects a nested TOML or YAML section. The default is
`"jam"`, so the TOML and YAML examples above put Jam settings below a `jam`
key. JSON configuration is read from its root object; its `pointer` argument
is currently not applied.

#### `JAM_CONFIG_CACHING`

Controls whether config files are parsed once and cached, or re-read on
every new instance. Defaults to `true`.

- `true` — the config file is parsed once when the first `Jam(config_path)`
  (or any config-driven module) is created. Later instances reuse the cached
  value. Use this in production: config is fixed at startup.
- `false` — each new instance re-reads the config file (including
  `$ENV` substitution), so you can change config at runtime without
  restarting the process.

The cache is keyed by config path and pointer. To invalidate it manually,
call `jam.utils.config_maker.__config_cache_clear__()`.
