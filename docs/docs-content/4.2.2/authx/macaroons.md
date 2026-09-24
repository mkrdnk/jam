# Macaroons

Macaroons are attenuable bearer credentials. A holder can append restrictions
without knowing the root secret. Existing caveats and root claims cannot be
removed or changed without invalidating the signature.

Jam combines authority as:

```text
root permissions
AND every credential constraint
AND server-side policy
```

!!! tip
    Jam deliberately keeps Macaroon caveats simple. Each caveat represents one
    restriction, and all caveats are combined with AND. Complex Boolean and
    allow/deny logic belongs in server-side `authz.rules`.

## Use in instance

### Config

The Macaroon profile requires a dedicated KeyChain. It must use
`MACAROON-HMAC-SHA256`; this is not the JOSE `HS256` algorithm.

Args:

* `keychain`: `str` - Name of the KeyChain. Required.
* `location`: `str = ""` - Unsigned location hint. Jam does not make an HTTP
  request to this address.
* `issuer`: `str | None = None` - Expected issuer. Issued credentials receive
  this value and authentication requires an exact match.
* `audience`: `str | None = None` - Expected audience. Issued credentials
  receive this value and authentication requires an exact match.
* `leeway`: `float = 0` - Non-negative clock tolerance in seconds for
  `expires_at` and `not_before`.
* `limits`: `dict[str, int] | None` - Parser and verifier resource limits.
* `list`: `str | dict[str, Any] | None` - Named or inline token list.
  See: [Lists](/latest/authx/lists).

Limit args:

* `serialized_size`: `int = 65536` - Maximum serialized token size in bytes.
* `caveat_payload_size`: `int = 8192` - Maximum data size of one caveat.
* `caveat_count`: `int = 64` - Maximum caveats across the verified graph.
* `discharge_count`: `int = 32` - Maximum supplied discharge Macaroons.
* `discharge_depth`: `int = 8` - Maximum nested discharge depth. The primary
  Macaroon has depth 0.

All limit values must be non-negative integers, not `bool`.

KeyChain args:

* `type`: `str` - `Memory` / `FileStorage`.
* `algorithm`: `str = "MACAROON-HMAC-SHA256"` - Macaroon root-key algorithm.
* `purpose`: `str | None = "local"` - Key purpose metadata.
* `path`: `str` - Required for `FileStorage`.

```toml
[jam.keychains.macaroons]
type = "FileStorage"
path = "/var/lib/my-service/macaroon-keys"
algorithm = "MACAROON-HMAC-SHA256"

[jam.macaroon]
keychain = "macaroons"
list = "credentials"
location = "https://api.example"
issuer = "https://api.example"
audience = "documents-api"
leeway = 0

[jam.macaroon.limits]
serialized_size = 65536
caveat_payload_size = 8192
caveat_count = 64
discharge_count = 32
discharge_depth = 8
```

Keys must be provisioned explicitly. Newly issued credentials use the current
key, retired keys continue verifying existing and attenuated credentials, and
revoked keys no longer verify. The signed root identifier contains the `kid`
used to resolve the historical key.

### Usage

```python
from jam import Jam

jam = Jam(config="config.toml")
```

#### Provision a key

Method: `jam.keychains[name].rotate`

```python
jam.keychains["macaroons"].rotate("root-2026-01")
```

#### Issue a Macaroon

Method: `jam.issue` with `via="macaroon"`

Args:

* `subject`: `BaseSubject | dict[str, Any]` - Credential subject.
* `permissions`: `list[str] | None` - Root permission grants.
* `exp`: `int | None` - Lifetime in seconds, represented as an `expires_at`
  caveat.
* `nbf`: `int | None` - Offset in seconds, represented as a `not_before`
  caveat.
* `iss`: `str | None` - Immutable issuer claim.
* `aud`: `str | None` - Immutable audience claim.
* `jti`: `str | None` - Immutable credential identifier.
* `**claims`: `Any` - Additional immutable root claims.

Returns:

`str`: Standard base64url-encoded binary v2 Macaroon.

```python
token = jam.issue(
    {"id": "42", "tenant": "example"},
    via="macaroon",
    permissions=["documents:*"],
    exp=3600,
    iss="example",
    aud="api",
)
```

`exp` and `nbf` are caveats, not root claims. Authentication rejects a
credential outside either time boundary. The compiled constraints are retained
and evaluated again during authorization.

Macaroons provide integrity, not confidentiality. Root claims are visible in
the serialized identifier; do not include secrets or sensitive plaintext.

#### Attenuate a Macaroon

Method: `jam.macaroon.decode`, then `macaroon.add_caveat`

```python
from jam.macaroons import Caveat

macaroon = jam.macaroon.decode(token)
delegated = macaroon.add_caveat(
    Caveat("permission", "documents:read"),
).add_caveat(
    Caveat(
        "condition",
        {
            "field": "context.resource.owner_id",
            "operator": "eq",
            "value": "@subject.id",
        },
    ),
)
delegated_token = delegated.encode()
```

`add_caveat()` returns a new immutable copy. The original credential is not
modified. `decode()` only parses a token; it does not authenticate it.

#### Authenticate a Macaroon

Method: `jam.authenticate` with `via="macaroon"`

Args:

* `token`: `str` - Primary serialized Macaroon.
* `discharges`: `Sequence[str | bytes] | None` - Serialized bound discharge
  Macaroons required by third-party caveats.

Returns:

`Principal`: Authenticated subject, immutable root claims, token type, and
compiled credential constraints.

```python
principal = jam.authenticate(delegated_token, via="macaroon")
print(principal.subject["id"])
>>> 42
```

Authentication verifies the complete signature and discharge graph before
parsing structured caveats or calling satisfiers. Request- and resource-based
conditions are not evaluated yet. Time boundaries and configured issuer and
audience are enforced during authentication.

#### Authorize a principal

Method: `jam.authorize`

```python
from jam import AuthorizationContext

owned = AuthorizationContext(resource={"owner_id": "42"})
other = AuthorizationContext(resource={"owner_id": "7"})

assert jam.authorize(principal, "documents:read", owned)
assert not jam.authorize(principal, "documents:write", owned)
assert not jam.authorize(principal, "documents:read", other)
```

Credential constraints are checked before the configured policy. A custom
policy cannot bypass a failing constraint or broaden the root permissions.

#### Access the module directly

`jam.macaroon` exposes the configured `MacaroonModule`:

```python
decoded = jam.macaroon.decode(token)
claims, constraints = jam.macaroon.authenticate(token)
```

The concrete module's `issue()` and `authenticate()` methods are KeyChain-backed
Jam profile extensions. They are not requirements of `BaseMacaroon`.

## Built-in caveats

### Permission

Name: `permission`

Value: `str`

```python
Caveat("permission", "documents:read")
Caveat("permission", "documents:*")
Caveat("permission", "*")
```

The caveat restricts the permission passed to `authorize()`. Multiple
permission caveats intersect; a later wildcard cannot broaden an earlier
restriction.

### Condition

Name: `condition`

Value args:

* `field`: `str` - Path rooted at `subject.*`, `token.*`, or `context.*`.
* `operator`: `str = "eq"` - Comparison operator.
* `value`: `Any` - Constant or `@subject.*`, `@token.*`, or `@context.*`
  reference.
* `timezone`: `str | None` - IANA timezone used for datetime evaluation.

```python
Caveat(
    "condition",
    {
        "field": "context.request.ip",
        "operator": "ip_in_network",
        "value": "10.0.0.0/8",
    },
)
```

Operators:

* `exists`, `truthy`
* `eq`, `ne`
* `in`, `not_in`
* `contains`, `contains_any`, `contains_all`
* `starts_with`, `ends_with`, `matches`
* `ip_in_network`
* `between`, `gt`, `gte`, `lt`, `lte`

`all`, `any`, `not`, and nested Boolean expressions are intentionally
unsupported. Missing runtime data, missing references, and incompatible types
deny authorization.

Credential-controlled regular expressions use a restricted subset: at most 256
characters, 16 flat alternatives, and one `*`, `+`, or `?` repetition per
branch. Groups, backreferences, and brace quantifiers are rejected; input is
limited to 4096 characters. The same restrictions apply to patterns resolved
through `@` references. Server-side `authz.rules` retain their existing regex
semantics.

Constraint evaluation reads stored values without invoking arbitrary
properties or user-defined comparison magic methods.

### Time boundaries

Names: `expires_at`, `not_before`

Value: timezone-aware ISO 8601 `str`

```python
Caveat("expires_at", "2026-06-01T12:00:00Z")
Caveat("not_before", "2026-06-01T11:00:00+00:00")
```

`expires_at` requires `context.now < value + leeway`; `not_before` requires
`context.now >= value - leeway`. Malformed or timezone-naive values raise
`InvalidCaveatError`. An unsatisfied boundary fails authentication. The same
boundary remains attached to the principal and is checked again during
authorization.

## Custom caveats

Module: `jam.macaroons.CaveatRegistry`

Method: `registry.register`

Args:

* `name`: `str` - Nonempty custom caveat name.
* `compiler`: `Callable[[Any], AuthorizationConstraint]` - Validates caveat
  data and returns a generic authorization constraint.

Returns:

`CaveatRegistry`: The same registry instance.

```python
from jam import Jam
from jam.authz import ConditionConstraint
from jam.macaroons import CaveatRegistry

registry = CaveatRegistry()
registry.register(
    "tenant",
    lambda value: ConditionConstraint(
        field="context.attributes.tenant",
        value=value,
    ),
)
jam = Jam(config="config.toml", caveat_registry=registry)
```

Registries belong to the instance. Built-in names cannot be replaced. Unknown
or malformed structured caveats fail authentication with
`InvalidCaveatError`.

## Third-party caveats

A third-party caveat requires a discharge Macaroon issued by another
authority. `location` is a hint only; Jam never fetches a discharge.

```python
from jam.macaroons import Caveat, Macaroon

primary = jam.macaroon.decode(token).add_third_party_caveat(
    caveat_root_key,
    "account-approved",
    location="https://approver.example",
)
discharge = Macaroon.create_discharge(
    caveat_root_key,
    "account-approved",
).add_caveat(
    Caveat("permission", "documents:read"),
)
bound = discharge.bind(primary)

principal = jam.authenticate(
    primary.encode(),
    via="macaroon",
    discharges=[bound.encode()],
)
```

The application is responsible for obtaining the discharge and transferring
the caveat root key to its issuer over a trusted channel. Missing, tampered,
incorrectly bound, or ambiguous discharges fail authentication. First-party
caveats from every validated discharge become mandatory constraints. Nested
discharges are supported within the configured limits, and every discharge is
bound to the final primary Macaroon.

## Opaque caveats

Opaque bytes or strings are supported by the protocol-level API:

```python
macaroon = jam.macaroon.decode(token).add_caveat(b"account = 42")
jam.macaroon.satisfy_exact(b"account = 42")
principal = jam.authenticate(macaroon.encode(), via="macaroon")
```

Use `satisfy_general(callback)` for application predicates. An opaque caveat
without a matching exact or general satisfier fails closed. Signature
verification completes before callbacks run; callback failures become
verification failures. Structured callbacks receive deeply immutable JSON
snapshots; objects are read-only mappings and arrays are tuples.

Structured caveats use deterministic `jam:v1:<base64url>` payloads containing
exactly `name` and `value`. This is the caveat namespace, not the complete token
format.

## Use out of instance

### Built

Module: `jam.macaroons.MacaroonModule`

Args:

* `keychain`: `BaseKeyChain | None = None` - Optional managed-key profile.
  Explicit-key protocol operations do not require it.
* `location`: `str = ""` - Default location used by KeyChain-backed
  `issue()`. It does not affect the explicit `encode(..., location=...)`
  argument.
* `limits`: `Limits = DEFAULT_LIMITS` - Resource bounds.
* `registry`: `CaveatRegistry | None = None` - Jam structured-caveat registry.
* `issuer`: `str | None = None` - Expected Jam profile issuer.
* `audience`: `str | None = None` - Expected Jam profile audience.
* `leeway`: `float = 0` - Time-boundary tolerance in seconds.

Returns:

`MacaroonModule`: Standalone protocol module. It implements `BaseMacaroon`.

```python
from jam.macaroons import MacaroonModule

macaroon = MacaroonModule()
```

### Encode a token

Method: `macaroon.encode`

Args:

* `identifier`: `bytes | str` - Nonempty opaque root identifier.
* `root_key`: `bytes | str` - Explicit root secret.
* `location`: `str = ""` - Unsigned location hint.

Returns:

`str`: Serialized standard binary v2 Macaroon.

```python
from secrets import token_bytes

root_key = token_bytes(32)
token = macaroon.encode(
    "credential-id",
    root_key,
    location="https://api.example",
)
```

### Decode a token

Method: `macaroon.decode`

Args:

* `token`: `bytes | str` - Serialized Macaroon.

Returns:

`Macaroon`: Unverified model suitable for inspection and attenuation.

```python
decoded = macaroon.decode(token)
delegated = decoded.add_caveat(b"account = 42")
```

### Verify a token

Method: `macaroon.verify`

Args:

* `token`: `bytes | str` - Serialized primary credential.
* `root_key`: `bytes | str` - Explicit root secret.
* `discharges`: `Iterable[bytes | str] = ()` - Serialized bound discharges.
* `structured_satisfiers`: `Mapping[str, Callable[[Any], bool]] | None` -
  Structured caveat callbacks.
* `collect_structured`: `bool = False` - Collect unknown structured caveats
  instead of rejecting them.

Returns:

`VerificationResult`: Structured caveats from the verified graph.

```python
macaroon.satisfy_exact(b"account = 42")
result = macaroon.verify(delegated.encode(), root_key)
```

Unknown caveats fail closed by default. `collect_structured=True` deliberately
defers structured-caveat policy evaluation: the caller must enforce every
returned caveat before granting access. Signature verification alone does not
satisfy deferred restrictions.

### Add a first-party caveat

Method: `Macaroon.add_caveat`

Args:

* `caveat`: `Caveat | bytes | str` - Structured or opaque predicate.

Returns:

`Macaroon`: New attenuated copy.

```python
from jam.macaroons import Caveat

delegated = decoded.add_caveat(Caveat("tenant", "example"))
```

### Add a third-party caveat

Method: `Macaroon.add_third_party_caveat`

Args:

* `caveat_root_key`: `bytes | str` - Secret shared with the discharge issuer.
* `identifier`: `bytes | str` - Discharge identifier.
* `location`: `str = ""` - Third-party location hint.

Returns:

`Macaroon`: New copy requiring a discharge.

### Bind a discharge

Method: `discharge.bind`

Args:

* `primary`: `Macaroon | bytes` - Final primary Macaroon or its signature.

Returns:

`Macaroon`: Discharge bound to the primary.
