---
title: PASETO
---

## Use in instance

### Config

Args:

* `version`: `str` - PASETO version(v1 / v2 / v3 / v4).
* `purpose`: `str` - `local` / `public`.
* `secret_key`: `str | None`: Secret key for PASETO.


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
>>> 1772132706
```

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
* `serializer`: `type[BaseEncoder] | BaseEncoder = JamEncoder` - JSON serializer.

Returns:

`tuple[dict[str, Any], dict[str, Any] | str, | None]` - Decoded payload and footer.

```python
payload, footer = paseto.decode(
    token=token,
    check_exp=True,
    check_list=False
)
print(payload)
>>> {
        'id': 1,
        'role': 'admin'
    }
print(footer)
>>> "some_footer_as_string"
```
