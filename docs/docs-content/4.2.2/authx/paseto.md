# PASETO

## Use in instance

### Config

Args:

* `version`: `str` - PASETO version(v1 / v2 / v3 / v4).
* `purpose`: `str` - `local` / `public`.
* `secret_key`: `str | None`: Secret key for PASETO.
* `list`: `str | dict[str, Any] | None` - Named or inline token list.
  See: [Lists](/latest/authx/lists).


```toml
[jam.paseto]
version = "v4"
purpose = "local"
secret_key = "3KVs1nMaWb8jP0_aYMhsRN_hHf9dwV1UdqKk_wUXlnM"
```

### Usage

```python
from jam import Jam

jam = Jam(config="config.toml")
```

#### Issue a token

Method: `jam.issue`

```python
token = jam.issue(
    {"id": 1, "role": "admin"},
    via="paseto",
    exp=3600,
)
print(token)
>>> v4.local.wTgWfsaSTjBcuZSqI7mT...
```

#### Authenticate a token

Method: `jam.authenticate`

```python
principal = jam.authenticate(token, via="paseto")
print(principal.subject["role"])
>>> admin
print(principal.claims["exp"])
>>> 2026-02-26T22:05:06Z
```

`exp` and `nbf` passed to `jam.issue` are relative durations in seconds.
PASETO stores the resulting instants as RFC 3339 UTC DateTime strings, as
required by the PASETO registered-claims specification.

Authentication validates both claims by default. A token is rejected after
its `exp` instant or before its `nbf` instant.

#### Access the module directly

`jam.paseto` exposes the configured `PASETOv*` instance. Encode/decode with
a custom payload and footer:

```python
token = jam.paseto.encode(
    payload={"id": 1, "role": "admin"},
    footer={"some": "footer", "as": "dict"},
)
payload, footer = jam.paseto.decode(token)
print(payload)
>>> {'id': 1, 'role': 'admin'}
print(footer)
>>> {'as': 'dict', 'some': 'footer'}
```

## Use out of instance

Modules:

* `jam.paseto.PASETOv1`
* `jam.paseto.PASETOv2`
* `jam.paseto.PASETOv3`
* `jam.paseto.PASETOv4`

For example, we will show how to work with v4.

### Built

Method: `PASETOv4.key`

Args:

* `purpose`: `str` - `local` / `public`.
* `secret_key`: `str | bytes`: Symmetric key for local and Asymmetric key for public.

Returns:

`PASETOv4`: Built PASETOv4 instance.

```python
from jam.paseto import PASETOv4

paseto = PASETOv4.key(
    purpose="local",
    secret_key="3KVs1nMaWb8jP0_aYMhsRN_hHf9dwV1UdqKk_wUXlnM"
)
```

### Encode token

Method: `paseto.encode`

Args:

* `payload`: `dict[str, Any]` - Token payload.
* `footer`: `dict[str, Any] | str | None = Non` - Token footer.
* `implicit_assertion`: `bytes | str = b""` - Additional authenticated data
  for v3 and v4.
* `serializer`: `type[BaseEncoder] | BaseEncoder = JamEncoder` - JSON serializer.

Returns:

`str`: PASETO.

```python
token = paseto.encode(
    payload={"id": 1, "role": "admin"},
    footer="some_footer_as_string"
)
print(token)
>>> v4.local.Py0Y4CbmylrmFo3F54u7l1gZCfd
```

### Decode token

Method: `paseto.decode`

Args:

* `token`: `str` - PASETO token.
* `implicit_assertion`: `bytes | str = b""` - Assertion that must match the
  value used while encoding a v3 or v4 token.
* `serializer`: `type[BaseEncoder] | BaseEncoder = JamEncoder` - JSON serializer.
* `validate_claims`: `bool = True` - Validate `exp` and `nbf` after
  cryptographic verification.

Returns:

`tuple[dict[str, Any], dict[str, Any] | str, | None]` - Decoded payload and footer.

```python
payload, footer = paseto.decode(
    token=token,
    validate_claims=True,
)
print(payload)
>>> {
        'id': 1,
        'role': 'admin'
    }
print(footer)
>>> "some_footer_as_string"
```

PASETO `exp` and `nbf` values are RFC 3339 DateTime strings:

```python
token = paseto.encode(
    {
        "id": 1,
        "exp": "2039-01-01T00:00:00Z",
        "nbf": "2038-12-31T23:00:00+00:00",
    }
)
payload, footer = paseto.decode(token)
```

Malformed claim values fail closed with `JamPASETOInvalidClaim`. Jam accepts
finite numeric Unix timestamps while decoding tokens issued by older Jam
versions, but newly issued PASETO credentials use RFC 3339.

Use `validate_claims=False` only when an application needs to inspect an
authenticated token regardless of its validity window:

```python
payload, footer = paseto.decode(token, validate_claims=False)
```

### Implicit assertions

PASETO v3 and v4 authenticate `implicit_assertion` without including it in
the token. Decoding with a missing or different assertion fails:

```python
token = paseto.encode(
    {"id": 1},
    implicit_assertion=b"tenant-a",
)
payload, footer = paseto.decode(
    token,
    implicit_assertion=b"tenant-a",
)
```

The v1 and v2 specifications do not define implicit assertions. Jam therefore
rejects a non-empty value on either encode or decode with
`JamPASETOImplicitAssertionUnsupported` instead of silently ignoring it.
Empty `b""` and `""` values remain valid. String assertions are encoded as
UTF-8.

| Version | Non-empty implicit assertion |
| --- | --- |
| v1 | Not supported |
| v2 | Not supported |
| v3 | Supported |
| v4 | Supported |

PASETO v1 public signatures created by 4.2.2 use the standard SHA-384
digest-size PSS salt. Verification also accepts signatures created by earlier
Jam releases with a maximum-length salt for upgrade compatibility.
