# Server side sessions

## Use in instance

### Config

Out of the box, Jam provides two types of sessions: `redis` and `json`.
To select the session type, you need to specify it in the configuration.
Different session types have different configuration parameters.

* `type`: `str` - `redis` / `json`
* `is_session_crypt`: `bool`:
* `serializer`: `BaseEncoder | type[BaseEncoder]` - Optional serializer for
  this session backend. It takes precedence over the root Jam serializer.

Sometimes you need to encrypt the session ID so that it cannot be forged. If you want to encrypt the session ID, set this parameter to True and pass the encryption key in the session_aes_secret parameter.

* `session_aes_secret`: `str` - The encryption key for the session ID. Key must be 32 url-safe base64-encoded bytes. You can use jam.utils.generate_aes_key to generate it. By default, Jam reads the key from the `JAM_SESSION_AES_SECRET` environment variable.

#### Redis

In Redis, sessions are stored as HASH,
where name is constructed from `<redis_sessions_key>:<session_key>`. The session ID is used as the key,
and a serialized JSON object with session data is used as the `value`.

Args:

* `redis_uri`: `str` - Redis address.
* `ttl`: `int` - Session lifetime in seconds.
* `redis_sessions_key`: `str` - Prefix for session keys in Redis. The default is `sessions`.

```toml
[jam.session]
type = "redis"
redis_uri = "redis://0.0.0.0:6379/0"
ttl = 3600
redis_sessions_key = "sessions"
```

#### JSON

In JSON, sessions are stored as files in the directory specified in the `json_path` parameter.

Args:

* `json_path`: `str` - Path to file.

```toml
[jam.session]
type = "json"
json_path = "sessions.json"
serializer = "my_package.serializers.SessionEncoder"
```

#### Custom

You can also implement your session module using the `BaseSession`.
interface and passing it to the config, for example, to store sessions in a database.

See: [Customization](/latest/dev/custom)


### Usage

```python
from jam import Jam

jam = Jam(config="config.toml")
```

#### Create a session via the facade

Method: `jam.issue` with `via="session"`

```python
session_id = jam.issue({"role": "admin"}, via="session")
print(session_id)
>>> 565df195-b963-4ebb-8978-318998ef191c
```

The `session_key` is read from `config.session.session_key` (defaults to
`"auth"`).

`exp` and `nbf` have the same relative-seconds input semantics as other
`jam.issue` modes. Jam stores absolute NumericDate values in the session,
along with `iss`, `aud`, and `jti` when supplied:

```python
session_id = jam.issue(
    {"id": "user-123", "role": "admin"},
    via="session",
    exp=3600,
    nbf=10,
    iss="accounts",
)
```

#### Authenticate a session

Method: `jam.authenticate` with `via="session"`

```python
principal = jam.authenticate(session_id, via="session")
print(principal.subject)
>>> {"role": "admin"}
```

Authentication validates the stored `exp` and `nbf` claims. It raises
`JamSessionExpired`, `JamSessionNotYetValid`, or `JamSessionInvalidClaim` for
an expired session, a session used too early, or a malformed NumericDate.
Validation is performed by the facade for every backend, including JSON
sessions that have no storage TTL. NumericDates must be finite integers or
floats; booleans, strings, NaN, and infinities are invalid, and `exp == now`
is expired.

#### Session CRUD via the module

`jam.session` exposes the configured session module directly:

##### Create session

Method: `jam.session.create`

Args:

* `session_key`: `str` - Key of session. Username for example.
* `data`: `dict[str, Any]` - Some data to store.

Returns:

`str`: Session ID.

```python
session_id = jam.session.create(
    session_key="user1",
    data={
        "role": "admin"
    }
)
```

##### Get session data

Method: `jam.session.get`

Args:

* `session_id`: `str` - Session ID.

Returns:

`dict[str, Any] | None`: Session data if session exists.

```python
data = jam.session.get(session_id)
print(data)
>>> {
        "role": "admin"
    }
```

##### Update session data

Method: `jam.session.update`

Args:

* `session_id`: `str` - Session ID.
* `data`: `dict[str, Any]`: New data.

Returns: `None`

```python
jam.session.update(
    session_id=session_id,
    data={
        "role": "banned"
    }
)
```

##### Delete session

Method: `jam.session.delete`

Args:

* `session_id`: `str` - Session ID.

Returns: `None`

```python
jam.session.delete(session_id)
```

##### Clear all user sessions

Method: `jam.session.clear`

Args:

* `session_key`: `str` - Session key.

Returns: `None`

```python
jam.session.clear(session_key="user1")
```

##### Session rework

Method: `jam.session.rework`

Args:

* `old_session_id`: `str` - Old session ID.

Returns:

`str`: New session ID.

```python
new_session_id = jam.session.rework(session_id)
```

## Use out of instance

### Redis

Module: `jam.sessions.redis.Redis`

Args:

* `redis_uri`: `str | Redis` - Redis URI or Redis instance.
* `redis_sessions_key`: `str = "sessions"` - Redis key for sessions.
* `ttl`: `int | None = 3600` - Session life time.
* `is_session_crypt`: `bool = False` - Encrypt session data.
* `session_aes_secret`: `bytes | str | None = None` - AES key for encrypting session data.
* `id_factory`: `Callable[[], str] = lambda: str(uuid4())` - Session ID factory.
* `serializer`: `BaseEncoder | type[BaseEncoder] = JsonEncoder` - JSON serializer.

```python
from jam.sessions import RedisSessions

session = RedisSessions(
    redis_uri="redis://localhost:6379",
    redis_sessions_key="sessions",
    ttl=3600,
)
```

### JSON

Module: `jam.sessions.json.JSONSessions`

Args:

* `json_path`: `str = sessions.json` - Path to json file.
* `is_session_crypt`: `bool = False` - Encrypt session data.
* `session_aes_secret`: `bytes | str | None = None` - AES key for encrypting session data.
* `id_factory`: `Callable[[], str] = lambda: str(uuid4())` - Session ID factory.
* `serializer`: `BaseEncoder | type[BaseEncoder] = JsonEncoder` - JSON serializer.

```python
session = JSONSessions(
    json_path="sessions.json",
)
```

## Serialization and lifecycle

The session serializer is selected in this order:

1. `jam.session.serializer`
2. the root `jam.serializer` or `Jam(serializer=...)`
3. `JsonEncoder`

The same precedence applies to `Jam` and `AsyncJam`, preserving data written
with a session-specific serializer.

Use synchronous resources as context managers, or call `close()` explicitly:

```python
from jam import Jam


with Jam(config="config.toml") as jam:
    session_id = jam.issue({"id": "user-123"}, via="session")
```

`Jam.close()` and `JSONSessions.close()` are idempotent. Redis session
backends close clients they create, but never close a caller-owned `redis`
client. Both synchronous and asynchronous Redis backends accept clients
configured for decoded string responses or raw byte responses, and preserve
empty session dictionaries during update and reissue.

### Create session

Method: `session.create`

Args:

* `session_key`: `str` - Session key.
* `session_data`: `dict` - Session data.

Returns:

`str`: Session ID

```python
session_id = session.create(
    session_key="user1",
    data={
        "name": "John",
        "age": 30
    }
)
print(session_id)
>>> 46782301-9068-46c8-a24c-b13666438026
```

### Get session data

Method: `session.get`

Args:

* `session_id`: `str` - Session ID.

Returns:

`dict[str, Any] | None`: Session data if session exists.

```python
session_data = session.get(session_id)
print(session_data)
>>> {'name': 'John', 'age': 30}
```

### Update session

Method: `session.update`

Args:

* `session_id`: `str` - Session ID.

Returns: `None`

```python
session.update(
    session_id=session_id,
    data={
        "name": "John",
        "age": 31
    }
)
```

### Delete session

Method: `session.delete`

Args:

* `session_id`: `str` - Session ID.

Returns: `None`

```python
session.delete(session_id)
```

### Clear all user sessions

Method: `session.clear`

Args:

* `session_key`: `str` - Session key.

Returns: `None`

```python
session.clear(session_key="user1")
```

### Session rework

Method: `session.rework`

Args:

* `session_id`: `str` - Session ID.

Returns:

`str`: New session ID.

```python
new_session_id = session.rework(
    session_id=session_id,
)
```
