# Principal

A **Principal** represents an authenticated Subject together with the claims provided by its credential.

When Jam successfully authenticates a credential, it creates a Principal:

```text
Credential
    │
    │ authentication
    ▼
Principal
    ├── subject
    ├── claims
    └── token_type
```

The Principal is the object you use after authentication to identify the authenticated Subject and inspect the information provided by its credential.

## Authenticating a Subject

A Principal is created by [`jam.authenticate()`](/api#jaminstance) after successful authentication.

```python
from jam import Jam

jam = Jam(config="config.toml")

principal = jam.authenticate(
    token,
    via="jwt",
)

print(principal.subject)
print(principal.claims)
print(principal.token_type)
```

For example, if the credential contains:

```json
{
  "sub": "1",
  "permissions": [
    "user:read",
    "post:read"
  ]
}
```

the resulting Principal contains the authenticated Subject and these claims:

```python
principal.subject
principal.claims
principal.token_type
```

## Subject

The `subject` attribute contains the Subject associated with the credential.

To restore a typed subject, pass its dataclass type when creating `Jam`:

```python
jam = Jam(config="config.toml", subject=User)
```

When the credential is authenticated by that instance, Jam builds a `User`
from the credential payload:

```python
principal.subject.id
principal.subject.name
principal.subject.role
```

Without a configured dataclass subject type, the decoded subject is a
dictionary:

```python
principal.subject["id"]
principal.subject["name"]
```

See [Subject](./subject) for more information.

## Claims

The `claims` attribute contains the claims declared by the credential.

```python
principal.claims
```

Claims are authentication-specific data carried by the credential. Jam does not require a fixed set of application claims, allowing credentials to carry additional information required by the application.

For example:

```python
principal.claims["email"]
principal.claims["tenant"]
```

The exact claims available depend on the authentication mechanism and the credential that was authenticated.

## Permissions

A Principal exposes permissions declared by its credential through the `permissions` property.

```python
principal.permissions
```

The property returns a `frozenset[str]`:

```python
frozenset({
    "user:read",
    "post:read",
    "post:create",
})
```

Jam also supports the `scope` claim as a source of permissions when the `permissions` claim is not present.

To check a single permission, use `has_permission()`:

```python
if principal.has_permission("post:read"):
    ...
```

`has_permission()` also handles permission grants according to Jam's permission matching rules.

## Token ID

If the credential contains a `jti` claim, it is available through the `jti` property:

```python
principal.jti
```

If the credential does not contain a valid string `jti` claim, the property returns `None`.
