---
title: Logging
---

Jam uses the standard library `logging`. Each module logs through a
module-level logger named after its module, e.g. `jam.jose.jwt`,
`jam.jose.__algorithms__`, `jam.sessions.json`.

Collect Jam logs with the standard Python API:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("jam")
```

The `"jam"` logger has a `NullHandler` attached, so Jam never logs
unhandled output on its own. Configure your own handlers as usual:

```python
import logging

handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
)
logging.getLogger("jam").addHandler(handler)
logging.getLogger("jam").setLevel(logging.DEBUG)
```

Because child loggers inherit from `"jam"`, configuring the parent
covers `jam.jose.*`, `jam.sessions.*`, `jam.paseto.*`, and the rest.

## Sensitive data redaction

By default, a `SensitiveDataFilter` is attached to the `"jam"` logger.
It scrubs tokens and secrets from every log record before it reaches a
handler, replacing them with `[REDACTED]`. This protects:

- JWS/JWT tokens (`header.payload.signature`)
- JWE tokens (five-segment compact serialization)
- PASETO tokens (`v2.local...`, `v3.public...`, ...)
- PEM-encoded private keys
- `key=value` style secrets (`secret`, `secret_key`, `client_secret`,
  `password`, `passphrase`, `token`, `api_key`, `private_key`, ...)

```python
import logging

from jam import Jam

logging.basicConfig(level=logging.INFO)

jam = Jam(config={...})
token = jam.jwt.encode(sub="123")
logger = logging.getLogger("jam")

logger.info("Issued token: %s", token)  # -> "Issued token: [REDACTED]"
```

The filter never drops records — it only rewrites the message.

### Disabling redaction

Redaction is enabled by default. During development you may want to see
the actual values in your logs. Set the environment variable
`JAM_DEBUG=True` before starting your process:

```bash
JAM_DEBUG=True python your_app.py
```

or construct a `SensitiveDataFilter` manually and control it directly:

```python
from jam.utils.redaction import SensitiveDataFilter

jam_logger = logging.getLogger("jam")
jam_logger.addFilter(SensitiveDataFilter(redact=False))
```

Note that Jam's own log calls already use lazy `%s` formatting, so token
values only materialize if the record is actually emitted.
