# Key rotation

Jam KeyChains let new JWTs use a new key without immediately invalidating
tokens signed by the previous key. This example uses persistent `RS256` keys
and performs the full standby, current, retired, and revoked lifecycle.

## Install and configure

```bash
pip install "jamlib[cli]"
mkdir -p jwt-keys
chmod 700 jwt-keys
```

Create `config.toml`:

```toml
[jam.keychains.jwt]
type = "FileStorage"
path = "jwt-keys"
algorithm = "RS256"

[jam.jose.jwt]
alg = "RS256"
keychain = "jwt"
```

!!! tip "Other configuration formats"
    The same configuration can be supplied as a Python dictionary, YAML, or
    JSON. TOML is convenient for sharing one configuration between the
    application and `jam keychain`.

Bootstrap the first key:

```bash
jam keychain --config config.toml add jwt 2026-01
jam keychain --config config.toml activate jwt 2026-01
jam keychain --config config.toml current jwt
```

## Observe a rotation

Create `rotate_demo.py`:

```python
from jam import Jam
from jam.exceptions import JamError


jam = Jam(config="config.toml")
chain = jam.keychains["jwt"]

old_token = jam.issue(
    {"id": "user-1"},
    via="jwt",
    exp=3600,
)
old_key_id = chain.current().id

chain.rotate("2026-02")
new_token = jam.issue(
    {"id": "user-1"},
    via="jwt",
    exp=3600,
)

assert jam.authenticate(old_token, via="jwt").subject["id"] == "user-1"
assert jam.authenticate(new_token, via="jwt").subject["id"] == "user-1"

chain.revoke(old_key_id)
try:
    jam.authenticate(old_token, via="jwt")
except JamError as error:
    print(error.error_code)

assert jam.authenticate(new_token, via="jwt").subject["id"] == "user-1"
```

Run it and inspect metadata:

```bash
python rotate_demo.py
jam keychain --config config.toml list jwt --include-revoked
```

JWT places the active key ID in the protected `kid` header. After rotation,
the previous key is `retired`: it no longer signs tokens but still verifies
them. Revocation is different—it immediately rejects every token using that
key.

## Operational rotation

For routine rotation:

```bash
jam keychain --config config.toml rotate jwt --key-id 2026-03
jam keychain --config config.toml list jwt
```

Keep a retired key until every token it signed has expired. Use `revoke` only
for compromise or another event requiring immediate invalidation, and remove
a key only after it is no longer needed for verification:

```bash
jam keychain --config config.toml revoke jwt 2026-02
jam keychain --config config.toml remove jwt 2026-02 --yes
```

Back up key storage, restrict it to the application user, perform rotation
through one controlled operator, and distribute verifier public keys before
activating a new asymmetric signing key.
