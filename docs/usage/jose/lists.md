---
title: Lists
---

## Use in instance

### Config

```toml

[jam.jose.jwt]
alg = "$JWT_ALG"
secret_key = "$JWT_SECRET_KEY"

[jam.jose.jwt.list]
type = "black"
backend = "redis"
redis_uri = "redis://localhost:6379"
ttl = 3600
```

Args:

* `type`: `str` - List type: `black` or `white`.
* `backend`: `str` - Storage backend: `redis`, `json`, `memory`.
* `redis_uri`: `str` - Redis connection URI (for redis backend).
* `json_path`: `str` - JSON file path (for json backend).
* `ttl`: `int` - Time to live in seconds (optional, for redis).
* `prefix`: `str` - Key prefix for namespacing.

### Usage

```python
from jam import Jam

jam = Jam(config="config.toml")
```

### Add token to list

Method: `jam.jwt.list.add`

Adds token to blacklist or whitelist.

Args:

* `token`: `str` - JWT token to add.

```python
jam.jwt.list.add(token=token)
```

### Check token in list

Method: `jam.jwt.list.check`

Checks if token is in list.

Args:

* `token`: `str` - JWT token to check.

Returns:

`bool`: `True` if token is in list, `False` otherwise.

```python
is_revoked = jam.jwt.list.check(token=token)
if is_revoked:
    print("Token is revoked")
```

### Delete token from list

Method: `jam.jwt.list.delete`

Removes token from list.

Args:

* `token`: `str` - JWT token to delete.

```python
jam.jwt.list.delete(token=token)
```

### Add multiple tokens

Method: `jam.jwt.list.add_many`

Adds multiple tokens to list.

Args:

* `tokens`: `list[str]` - List of JWT tokens.

```python
jam.jwt.list.add_many(tokens=[token1, token2, token3])
```

### Check multiple tokens

Method: `jam.jwt.list.check_many`

Checks multiple tokens in list.

Args:

* `tokens`: `list[str]` - List of JWT tokens.

Returns:

`dict[str, bool]`: Dict mapping tokens to their presence status.

```python
results = jam.jwt.list.check_many(tokens=[token1, token2])
print(results)
>>> {token1: True, token2: False}
```

### Delete multiple tokens

Method: `jam.jwt.list.delete_many`

Removes multiple tokens from list.

Args:

* `tokens`: `list[str]` - List of JWT tokens.

```python
jam.jwt.list.delete_many(tokens=[token1, token2])
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
