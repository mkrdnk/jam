---
title: Configuration
---

# Jam configuration

## Config


The configuration only works for `jam.Jam`/`jam.aio.Jam`.
Standalone modules such as `jam.jwt.JWT`, `jam.paseto.PASETOv4`, etc. are configured simply by the class's `__init__`. For each model, see the corresponding documentation.

### Instance

The `*.Jam` class itself has several parameters:
```python
from jam import Jam

jam = Jam(
    config="path/to/config/file.toml.yaml.json", # or python-dict
    pointer="jam",
    serializer=JsonEncoder
)
```

#### config: str | dict[str, Any]
This is the path to your config as a `string` or dict with the configuration:

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
        "key": os.getenv("PASETO_SECRET_KEY")
    }
    }
}

jam = Jam(config=config)
jwt = jam.jwt_encode(payload={"user": 1})
paseto = jam.paseto_create(payload={"user": 1}, footer=None)
```

##### TOML
```toml
[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[jam.paseto]
version = "v4"
purpose = "local"
key = "$PASETO_SECRET_KEY"
```
```python
from jam import Jam

jam = Jam(config="config.toml")
jwt = jam.jwt_encode(payload={"user": 1})
paseto = jam.paseto_create(payload={"user": 1}, footer=None)
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
    key: $PASETO_SECRET_KEY
```
```python
from jam import Jam

jam = Jam(config="config.yaml")
jwt = jam.jwt_encode(payload={"user": 1})
paseto = jam.paseto_create(payload={"user": 1}, footer=None)
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
    "key": "$PASETO_SECRET_KEY"
  }
}
```
```python
from jam import Jam

jam = Jam(config="config.json")
jwt = jam.jwt_encode(payload={"user": 1})
paseto = jam.paseto_create(payload={"user": 1}, footer=None)
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
jwt = jam.jwt_encode(payload={"user": 1})
paseto = jam.paseto_create(payload={"user": 1}, footer=None)
```

Our config file will look like this:
```toml
[anotherpointer.jose.jwt]  # pointer
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"

[anotherpointer.paseto]  # pointer
version = "v4"
purpose = "local"
key = "$PASETO_SECRET_KEY"
```

!!! tip
    This can be useful for configuring two instances of `Jam` in a single file, for example.

---

#### serializer: type[BaseEncoder] = JsonEncoder

JSON object serializer. By default, JsonEncoder is used, which utilizes sdtlib.json. 

It can also be passed in the config file as a string:
```toml
[jam]
serializer = "jam.encoders.JsonEncoder"

[jam.jose.jwt]
alg = "HS256"
secret_key = "$JWT_SECRET_KEY"
```

For more details, see the [documentation on serialization](/usage/serializers.md).

### Environment variables

Jam will automatically search for environment variables
if a value begins with `$` in config files. For python dict, use `os.getenv`.

Example:

```toml
[jam.jose.jwt]
alg = "$JWT_ALG"
secret_key = "$JWT_SECRET"
```

!!! note
    Some modules read certain environment variables by default, as described in detail in each module.

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
