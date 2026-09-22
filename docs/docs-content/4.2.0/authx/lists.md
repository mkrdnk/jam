# Lists

Lists make otherwise stateless JWT, PASETO, Macaroon, and SAML credentials
revocable. Each entry is the **complete serialized credential string**. Do not
add an identifier such as the JWT `jti` claim: authentication checks the
credential itself.

The existing configuration values are:

* `type = "black"`: a denylist. Issued tokens are not added automatically;
  call `add(token)` to revoke one.
* `type = "white"`: an allowlist. Tokens issued by the configured module are
  added automatically; removing a token revokes it.

## Configure a shared list

Lists are top-level named modules. JWT, PASETO, Macaroons, and SAML can
reference the same list or use different named lists.

```toml
[jam.lists.credentials]
type = "black"
backend = "redis"
redis_uri = "redis://localhost:6379"
ttl = 3600

[jam.jose.jwt]
alg = "$JWT_ALG"
secret_key = "$JWT_SECRET_KEY"
list = "credentials"

[jam.paseto]
version = "v4"
purpose = "local"
secret_key = "$PASETO_SECRET_KEY"
list = "credentials"

[jam.keychains.macaroons]
type = "Memory"
algorithm = "MACAROON-HMAC-SHA256"

[jam.macaroon]
keychain = "macaroons"
list = "credentials"

[jam.saml]
role = "sp"
entity_id = "https://sp.example.com"
idp_public_key = "path/to/idp_cert.pem"
list = "credentials"
```

Args:

* `type`: `str` - List type: `black` or `white`.
* `backend`: `str` - Storage backend: `redis`, `json`, `memory`.
* `redis_uri`: `str` - Redis connection URI (for redis backend).
* `json_path`: `str` - JSON file path (for json backend).
* `ttl`: `int` - Time to live in seconds (optional, for redis).
* `prefix`: `str` - Key prefix for namespacing.

An inline `list = { ... }` configuration remains supported for compatibility,
but named lists are preferred because they are reusable and have an explicit
storage namespace.

## Use in instance

```python
from jam import Jam

jam = Jam(config="config.toml")
token_list = jam.lists["credentials"]
```

`jam.jwt_list`, `jam.paseto_list`, `jam.macaroon_list`, and `jam.saml_list`
are convenience references to the selected entries in `jam.lists`.
Synchronous JWT and PASETO modules also expose the same store as
`jam.jwt.list` and `jam.paseto.list`.

A SAML IdP and SP normally use separate `Jam` instances. They must point to
the same persistent backend and prefix for an allowlist issued by the IdP to
be visible to the SP.

```python
token = jam.issue({"id": "user-123"}, via="paseto")
jam.lists["credentials"].add(token)

# Raises JamTokenInDenyList because the complete token was revoked.
jam.authenticate(token, via="paseto")
```

### Async usage

`AsyncJam` uses native asynchronous list backends for all four credential
types:

```python
from jam.aio import AsyncJam

jam = AsyncJam(config="config.toml")
token = await jam.issue({"id": "user-123"}, via="jwt")
await jam.lists["credentials"].add(token)

# Raises JamTokenInDenyList.
await jam.authenticate(token, via="jwt")
```

### Add token to list

Method: `jam.lists[name].add`

Adds token to blacklist or whitelist.

Args:

* `token`: `str` - Serialized credential to add.

```python
jam.lists["credentials"].add(token=token)
```

### Check token in list

Method: `jam.lists[name].check`

Checks if token is in list.

Args:

* `token`: `str` - JWT token to check.

Returns:

`bool`: `True` if token is in list, `False` otherwise.

```python
is_revoked = jam.lists["credentials"].check(token=token)
if is_revoked:
    print("Token is revoked")
```

### Delete token from list

Method: `jam.lists[name].delete`

Removes token from list.

Args:

* `token`: `str` - JWT token to delete.

```python
jam.lists["credentials"].delete(token=token)
```

### Add multiple tokens

Method: `jam.lists[name].add_many`

Adds multiple tokens to list.

Args:

* `tokens`: `list[str]` - List of JWT tokens.

```python
jam.lists["credentials"].add_many(tokens=[token1, token2, token3])
```

### Check multiple tokens

Method: `jam.lists[name].check_many`

Checks multiple tokens in list.

Args:

* `tokens`: `list[str]` - List of JWT tokens.

Returns:

`dict[str, bool]`: Dict mapping tokens to their presence status.

```python
results = jam.lists["credentials"].check_many(tokens=[token1, token2])
print(results)
>>> {token1: True, token2: False}
```

### Delete multiple tokens

Method: `jam.lists[name].delete_many`

Removes multiple tokens from list.

Args:

* `tokens`: `list[str]` - List of JWT tokens.

```python
jam.lists["credentials"].delete_many(tokens=[token1, token2])
```

## Use out of instance

### RedisList

Redis-based token list. Most optimal for production with TTL support.

Module: `jam.lists.redis.RedisList`

Args:

* `type`: `str` - List type: `black` or `white`.
* `prefix`: `str` - Key prefix for namespacing.
* `redis_uri`: `str` - Redis connection URI.
* `redis`: `Redis` - Pre-configured Redis client (optional).
* `ttl`: `int` - Time to live in seconds (optional).

```python
from jam.lists.redis import RedisList

list = RedisList(
    type="black",
    prefix="jwt",
    redis_uri="redis://localhost:6379",
    ttl=3600
)
list.add(token)
list.check(token)
list.delete(token)
```

!!! note "TTL behavior"
    When `ttl` is set, tokens automatically expire from the list after the
    specified number of seconds. This is useful for token blacklists where
    tokens should only be tracked until their natural expiration.

### MemoryList

In-memory token list. Simple but not persistent.

Module: `jam.lists.memory.MemoryList`

Args:

* `type`: `str` - List type: `black` or `white`.
* `prefix`: `str` - Key prefix for namespacing.

```python
from jam.lists.memory import MemoryList

list = MemoryList(
    type="black",
    prefix="jwt"
)
list.add(token)
list.check(token)
list.delete(token)
```

### JSONList

JSON file-based token list. Persistent but limited scalability.

Module: `jam.lists.json.JSONList`

Args:

* `type`: `str` - List type: `black` or `white`.
* `prefix`: `str` - Key prefix for namespacing.
* `json_path`: `str` - Path to JSON file.

```python
from jam.lists.json import JSONList

list = JSONList(
    type="black",
    prefix="jwt",
    json_path="blacklist.json"
)
list.add(token)
list.check(token)
list.delete(token)
```

## Methods comparison

| Method | MemoryList | RedisList | JSONList |
|--------|------------|----------|----------|
| `add` | ✓ | ✓ | ✓ |
| `delete` | ✓ | ✓ | ✓ |
| `check` | ✓ | ✓ | ✓ |
| `add_many` | ✓ | ✓ | ✓ |
| `delete_many` | ✓ | ✓ | ✓ |
| `check_many` | ✓ | ✓ | ✓ |
| TTL support | ✗ | ✓ | ✗ |
| Persistence | ✗ | ✓ | ✓ |

## Blacklist vs Whitelist

### Blacklist

Tokens in blacklist are rejected.

```python
list = RedisList(type="black", prefix="jwt", redis_uri="...")

# Token is in blacklist
if list.check(token):
    raise Exception("Token has been revoked")
```

### Whitelist

Only tokens in whitelist are accepted.

```python
list = RedisList(type="white", prefix="jwt", redis_uri="...")

# Token is not in whitelist
if not list.check(token):
    raise Exception("Token is not valid")
```
