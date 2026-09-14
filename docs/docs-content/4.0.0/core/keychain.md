# KeyChain

`KeyChain` separates credential key lifecycle from JWT and PASETO.  It stores
one current issuing key and any number of historical verification keys.  Key
metadata can be listed, but the library never returns private material from
the public administration API.

## Lifecycle

Keys are created as `standby`.  A standby or retired key can be made
`current`, which retires the previous current key.  Retired keys continue to
verify credentials.  `revoke` makes a key fail verification immediately.
`remove` permanently deletes a non-current key and must be a deliberate,
manual operation.

## Configuration

Define named chains independently, then reference them from credential
modules:

```toml
[jam.keychains.jwt]
type = "FileStorage"
path = "/var/lib/jam/keys/jwt"

[jam.jose.jwt]
alg = "HS256"
keychain = "jwt"

[jam.keychains.paseto]
type = "Memory"
purpose = "local"

[jam.paseto]
version = "v4"
purpose = "local"
keychain = "paseto"
```

`Memory` is suitable for tests and short-lived applications. `FileStorage`
keeps each key in its own owner-only (`0600`) file within an owner-only
(`0700`) directory, atomically persists writes, rejects symlinks, and uses an
advisory process lock. These controls prevent accidental corruption and
concurrent writers; they do not protect against an attacker who can already
modify the directory.

Existing `secret_key` configuration and direct `JWT`/PASETO construction
continue to work when `keychain` is omitted.

## Rotation and compromise response

Initial deployment: add a key, activate it, issue credentials, add a future
standby key, then activate that key when rotating. The old current key becomes
retired and verifies credentials until it is manually removed.

For a compromised key, revoke it immediately, then rotate or activate another
key. Credentials using the revoked key fail verification at once. Investigate
affected credentials and remove the key only when its removal is appropriate.

## CLI

`jam keys` remains the standalone generator. KeyChain administration is a
separate namespace and always goes through the KeyChain API:

```text
jam keychain --config jam.toml add jwt 2026-10
jam keychain --config jam.toml activate jwt 2026-10
jam keychain --config jam.toml rotate jwt
jam keychain --config jam.toml list jwt
jam keychain --config jam.toml revoke jwt 2026-09
jam keychain --config jam.toml remove jwt 2026-09 --yes
```

`show`, `list`, and `current` display IDs, state, creation time, algorithm,
and SHA-256 fingerprints only; they never print key material.
