# Macaroons

A macaroon is a delegable bearer credential: its holder can add restrictions
without knowing the root secret. Removing or changing already signed caveats,
root claims, or permissions invalidates the signature.

> Jam deliberately keeps caveats simple. Each caveat represents one
> restriction, and all caveats are combined with AND. Complex allow/deny logic
> and Boolean expressions belong in server-side `authz.rules`.

In Jam's authorization profile, effective permissions are the intersection of
root permissions, all credential restrictions, and server policy. Even a custom
policy that always returns `True` cannot bypass Macaroon constraints.

## Configuration

```python
from jam import Jam

jam = Jam(config={
    "keychains": {
        "access": {
            "type": "Memory",
            "algorithm": "MACAROON-HMAC-SHA256",
        },
    },
    "macaroon": {
        "keychain": "access",
        "location": "https://api.example",
    },
})
jam.keychains["access"].rotate("root-1")
```

Keys must be created explicitly. `Memory` does not preserve them across
restarts; use `FileStorage` for persistent storage.

### `macaroon` options

| Option | Type | Default | Purpose |
|---|---|---|---|
| `keychain` | `str` | Required | Name of the chain in `keychains`. |
| `location` | `str` | `""` | Unsigned service location hint, not an instruction to make an HTTP request. |
| `limits` | object | See the next table | Credential parsing and verification limits. |

### `macaroon.limits` options

Values must be non-negative integers, not `bool`.

| Option | Default | Purpose |
|---|---:|---|
| `serialized_size` | `65536` | Maximum size of a single serialized token in bytes. |
| `caveat_payload_size` | `8192` | Maximum payload size of a single caveat. |
| `caveat_count` | `64` | Maximum number of caveats in the chain being verified. |
| `discharge_count` | `32` | Maximum number of supplied discharges. |
| `discharge_depth` | `8` | Maximum nested discharge depth; the primary macaroon has depth 0. |

### Associated `keychains` entry

| Option | Type | Default / requirement |
|---|---|---|
| `type` | `"Memory"` or `"FileStorage"` | Required. |
| `algorithm` | `str` | `MACAROON-HMAC-SHA256` when the Macaroon module creates the chain; other algorithms are not supported. |
| `purpose` | `str` or `None` | Defaults to `"local"` when created through Macaroon. |
| `path` | `str` | Required for `FileStorage`; not used by `Memory`. |

The Macaroon algorithm is not JOSE `HS256`. Do not share a chain across
protocols. Rotation retires the current key, which can still verify existing
credentials. Revoking a key prevents verification of all its credentials,
including attenuated copies. The signed root `kid` identifies the required key.

## Standalone module

`MacaroonModule` implements `BaseMacaroon` and does not require a `Jam` instance.
The generic `BaseMacaroon` contract supports explicit-key encoding, decoding,
verification, and satisfier registration. It does not require a KeyChain,
claims, or Jam authorization constraints. `Macaroon` is the separate low-level
cryptographic token model.

### Explicit-key operations

```python
from secrets import token_bytes

from jam.macaroons import BaseMacaroon, MacaroonModule

root_key = token_bytes(32)
module: BaseMacaroon = MacaroonModule()
token = module.encode("credential-id", root_key, location="https://api.example")
delegated = module.decode(token).add_caveat(b"account = 42")
module.satisfy_exact(b"account = 42")
result = module.verify(delegated.encode(), root_key)
```

`encode(identifier, root_key, *, location="")` returns a serialized token.
`decode(token)` returns a `Macaroon`; `verify(token, root_key, discharges=(), ...)`
returns a `VerificationResult`. Use `satisfy_exact()` or `satisfy_general()` to
register handlers for opaque caveats.

`verify()` also accepts keyword-only `structured_satisfiers=None` and
`collect_structured=False`. Supply a mapping of caveat names to Boolean
callbacks through `structured_satisfiers` to evaluate structured caveats.
Unknown caveats fail closed by default. Setting `collect_structured=True`
deliberately defers unknown structured caveats: the caller must enforce every
collected caveat before granting access. Signature verification alone does not
satisfy these deferred restrictions.

### KeyChain-backed Jam profile

The concrete `MacaroonModule` also provides `issue(claims, ...)` and
`authenticate(token, discharges)`. These profile extensions require a KeyChain;
they are not abstract requirements of `BaseMacaroon`.

```python
from jam.keychain import Memory
from jam.macaroons import MacaroonModule

chain = Memory("MACAROON-HMAC-SHA256")
chain.rotate("root-1")
module = MacaroonModule(keychain=chain)
token = module.issue({"sub": "42", "permissions": ["documents:read"]})
claims, constraints = module.authenticate(token)
```

`MacaroonModule` arguments:

| Argument | Type | Default |
|---|---|---|
| `keychain` | `BaseKeyChain` or `None` | `None`; required for the Jam profile's `issue()` and `authenticate()`. |
| `registry` | `CaveatRegistry` or `None` | A new, empty registry of custom caveats. |
| `location` | `str` | `""`. |
| `limits` | `Limits` | `Limits()` with the values listed above. |

`decode()` decodes a token for inspection or attenuation but **does not verify
authenticity**. Use `verify()` for explicit-key verification or `authenticate()`
for the KeyChain-backed Jam profile.
`create_instance()` constructs the module from configuration and a supplied
KeyChain resolver; the `Jam` facade does not contain Macaroon configuration
rules.

## Issuance and attenuation

```python
from jam import AuthorizationContext
from jam.macaroons import Caveat

token = jam.issue(
    {"id": "42"},
    via="macaroon",
    permissions=["documents:*"],
    exp=3600,
    iss="example",
    aud="api",
    jti="request-credential",
)
delegated = jam.macaroon.decode(token).add_caveat(
    Caveat("permission", "documents:read"),
).add_caveat(
    Caveat("condition", {
        "field": "context.resource.owner_id",
        "operator": "eq",
        "value": "@subject.id",
    }),
)
principal = jam.authenticate(delegated.encode(), via="macaroon")
allowed = jam.authorize(
    principal,
    "documents:read",
    AuthorizationContext(resource={"owner_id": "42"}),
)
```

Root claims contain the subject (`sub`), permissions, issuer, audience, jti, and
additional application claims. They cannot be changed without invalidating the
signature. `exp` and `nbf` are specified in seconds relative to issuance and
become time caveats rather than root claims.

`add_caveat()` returns a new copy; the original token is unchanged.
`authenticate()` verifies the primary and discharge signatures, then validates
the caveats and compiles `Principal.constraints`. Request and resource data
are checked only in `authorize()`.

## Built-in caveats

### `permission`

```python
Caveat("permission", "documents:read")
Caveat("permission", "documents:*")
Caveat("permission", "*")
```

Restricts the requested `permission` argument. Multiple caveats intersect:
a subsequent `*` cannot broaden an earlier `documents:read`.

### `condition`

A single comparison rooted at `subject.*`, `token.*`, or `context.*`.

```python
Caveat("condition", {
    "field": "context.request.ip",
    "operator": "ip_in_network",
    "value": "10.0.0.0/8",
})
Caveat("condition", {
    "field": "token.tenant",
    "operator": "eq",
    "value": "@context.attributes.tenant",
})
```

Operators: `exists`, `truthy`, `eq`, `ne`, `in`, `not_in`, `contains`,
`contains_any`, `contains_all`, `starts_with`, `ends_with`, `matches`,
`ip_in_network`, `between`, `gt`, `gte`, `lt`, `lte`. References to
`@subject.*`, `@token.*`, and `@context.*` are supported, as is `timezone`
for time comparisons. `all`, `any`, `not`, and nested Boolean expressions
are prohibited.

Unavailable runtime data, missing references, and incompatible types cause
denial. Credential evaluation uses safe field access without invoking arbitrary
properties and a restricted regular expression subset: an untrusted token must
not trigger unsafe computation on the server. Server-side `authz.rules` retain
their existing semantics.

For `matches`, patterns may contain up to 256 characters and 16 flat
alternatives (such as `admin|owner`), with at most one `*`, `+`, or `?`
repetition per branch. Groups, backreferences, and brace quantifiers are
prohibited; the input string is limited to 4096 characters. These limits also
apply to patterns obtained through `@` references.
A missing field always denies access, including with `exists=False`.
Comparisons operate on plain built-in values, not objects with custom
`__eq__`, `__bool__`, or other magic methods.

### `expires_at` and `not_before`

```python
Caveat("expires_at", "2026-06-01T12:00:00Z")
Caveat("not_before", "2026-06-01T11:00:00+00:00")
```

The conditions are `context.now < expires_at` and `context.now >= not_before`.
Values must be timezone-aware ISO 8601 timestamps; UTC is used internally.
An invalid format or a missing timezone raises `InvalidCaveatError` during
authentication. A valid but unsatisfied caveat yields `False` during
authorization.

## Custom caveats

```python
from jam.authz import ConditionConstraint
from jam.macaroons import CaveatRegistry

registry = CaveatRegistry()
registry.register("tenant", lambda value: ConditionConstraint(
    field="context.attributes.tenant",
    value=value,
))
jam = Jam(config=config, caveat_registry=registry)
```

The registry belongs to the instance. A compiler accepts and validates caveat
data, then returns an `AuthorizationConstraint` with a pure `check()` method.
Built-in names cannot be overridden. Unknown or malformed caveats are rejected
with `InvalidCaveatError`. When needed, handlers can be registered directly in
the standalone module's registry.

## Opaque caveats

The low-level model accepts arbitrary bytes or strings:

```python
from jam.macaroons import Macaroon, Verifier

credential = Macaroon.create(root_key, "credential-id")
credential = credential.add_caveat(b"account = 42")
verifier = Verifier()
verifier.satisfy_exact(b"account = 42")
verifier.satisfy_general(lambda data: data == b"application:approved")
verifier.verify(credential, root_key)
```

Without a matching satisfier, verification of an opaque caveat fails.
Signatures are verified before handlers are invoked. For dynamic restrictions
in Jam, use structured caveats compiled into principal constraints.

Structured data uses the `jam:v1:<base64url>` format with compact,
deterministic JSON `{"name": ..., "value": ...}`. This is a caveat namespace,
**not the token format itself**. Unsupported versions are rejected.
The complete credential uses the standard Macaroon v2 packet format.

## Third-party caveats and discharges

```python
from jam.macaroons import Macaroon

primary = jam.macaroon.decode(token).add_third_party_caveat(
    caveat_root_key,
    "account-approved",
    location="https://approver.example",
)
discharge = Macaroon.create_discharge(
    caveat_root_key,
    "account-approved",
).add_caveat(Caveat("permission", "documents:read"))
bound = discharge.bind(primary)

principal = jam.authenticate(
    primary.encode(),
    via="macaroon",
    discharges=[bound.encode()],
)
```

The application obtains discharges from the third-party service itself: Jam
does not make HTTP requests to `location`. The caveat secret must be sent to
the trusted party over a secure channel and is not disclosed to the primary
macaroon's holder.

Each discharge is bound to the final primary macaroon. If the primary changes,
the binding must be repeated. A missing, modified, or incorrectly bound
discharge, or an incorrect key, prevents authentication. Constraints from all
verified discharges are added to the primary's constraints. Nested discharges
are supported, subject to depth, count, and size limits.

## Asynchronous facade

`AsyncJam` uses the same standalone module. Calls to `issue()` and
`authenticate()` are awaited; `authorize()` remains synchronous.
Cryptographic operations and processing the supplied discharges perform no
network I/O.

## Dependencies

Macaroons require only Jam's existing `cryptography` dependency. The internal
SecretBox implementation uses standard HSalsa20/XSalsa20 with Poly1305 from
`cryptography`, retaining the NaCl-compatible nonce, tag, and ciphertext format.
It does not substitute AES-GCM or introduce a new Macaroon protocol.

The Salsa20 implementation is pure Python and does not guarantee constant-time
execution. It is not suitable for deployments whose threat model includes
local or high-resolution timing attackers. Authentication tags are verified by
`cryptography` before plaintext is returned, but that does not make the
keystream computation constant-time. Compatibility is tested against published vectors and reference
implementations; those tests do not constitute an independent cryptographic
audit.

Neither PyNaCl nor PyMacaroons is a runtime dependency or an optional extra.
They can be installed temporarily to run differential interoperability tests.
