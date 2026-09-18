# KeyChain

`jam.keychain` manages the signing or encryption keys used by JWT and PASETO.
It supports safe key rotation: newly issued credentials use the current key,
while credentials issued by retired keys remain verifiable until those keys are
revoked or removed.

Use a KeyChain when credentials must survive key rotation. A configured chain
is available through `jam.keychains`.

## Lifecycle

Each key has one of these statuses:

| Status | Issuing | Verification | Description |
|--------|---------|--------------|-------------|
| `standby` | No | Yes | A generated or supplied key waiting to be activated. |
| `current` | Yes | Yes | The one key used to issue new credentials. |
| `retired` | No | Yes | A former issuing key kept for existing credentials. |
| `revoked` | No | No | A compromised key; credentials using it are rejected. |

`activate()` makes a standby or retired key current and retires the previous
current key. `rotate()` generates and activates a new key in one operation.
Only non-current keys can be removed.

## Configuration

Configure chains in the `keychains` section and attach one by name to a JWT or
PASETO module. `Memory` is useful for tests and short-lived processes;
`FileStorage` persists key material between process restarts.

```toml
[jam.keychains.jwt]
type = "FileStorage"
path = "/var/lib/my-service/jwt-keys"
algorithm = "RS256"

[jam.jose.jwt]
alg = "RS256"
keychain = "jwt"
```

The storage directory must be owned by the process user. `FileStorage` creates
it with `0700` permissions and stores key files with `0600` permissions.
It rejects symlinks, unsafe permissions, and files not owned by that user.

For an in-memory chain:

```toml
[jam.keychains.access]
type = "Memory"
algorithm = "HS256"

[jam.jose.jwt]
alg = "HS256"
keychain = "access"
```

`algorithm` defaults to the algorithm of the module using the chain. For
PASETO, set `purpose` to the module's `local` or `public` purpose:

```toml
[jam.keychains.paseto]
type = "FileStorage"
path = "/var/lib/my-service/paseto-keys"
purpose = "local"

[jam.paseto]
version = "v4"
purpose = "local"
keychain = "paseto"
```

When a KeyChain is configured, do not also configure `secret_key` for that
JWT or PASETO module.

## Using a chain directly

`Memory` and `FileStorage` implement `BaseKeyChain`. Create a key, activate it,
then pass the chain to a module:

```python
from jam.jose import JWT
from jam.keychain import Memory

chain = Memory(algorithm="HS256")
chain.add("2026-03")
chain.activate("2026-03")

jwt = JWT(alg="HS256", keychain=chain)
token = jwt.encode(payload={"sub": "user-42"})

chain.rotate("2026-04")
assert jwt.decode(token)["payload"]["sub"] == "user-42"
```

Generated material is supported for `HS*`, `RS*`, `ES256`, `ES384`, `ES512`,
`EdDSA`/`Ed25519`, and PASETO `local`. You may pass bytes or a string as the
second argument to `add()` when importing existing material:

```python
chain.add("imported", material=existing_private_key)
```

Key IDs must be non-empty and file-name-safe: they cannot contain `/`, `\`,
`.` or `..`.

## Rotation and revocation

Retired keys verify existing credentials, so rotate before removing the old
key. Revocation has an immediate effect: verification of any credential issued
with the revoked key fails.

```python
chain.rotate("2026-04")       # A new current key; 2026-03 becomes retired.
chain.revoke("2026-03")       # Reject credentials signed with 2026-03.
chain.remove("2026-03")       # Permanently delete it when it is no longer needed.
```

Key metadata is available without exposing key material:

```python
for key in chain.list(include_revoked=False):
    print(key.id, key.status, key.fingerprint)
```

JWT stores the key ID in its `kid` header. PASETO stores it in the token footer
and preserves an application-provided footer inside its KeyChain metadata; the
decoded value is the original application footer.

## CLI administration

Install the CLI extra and pass the same configuration file used by the
application:

```bash
pip install "jamlib[cli]"

jam keychain --config config.toml rotate jwt --key-id 2026-04
jam keychain --config config.toml list jwt
jam keychain --config config.toml revoke jwt 2026-03
```

The CLI never displays private key material. Run `jam keychain --help` for the
full command list.
