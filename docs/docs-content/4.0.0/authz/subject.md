# Subject

A **Subject** represents an entity that can be authenticated by Jam and authorized to perform actions.

A Subject can represent anything that needs to have an identity within your application:

* User
* Service
* Device
* Application
* Any other entity

!!! note "Subject is not an authentication method"
    A Subject represents **who** is being authenticated, while an authentication method defines **how** that Subject is authenticated.

For example, the same Subject can be authenticated using JWT, PASETO, a session, or another authentication mechanism supported by Jam.

## Creating a Subject

A Subject must be a `dataclass` and must define an `id` field containing a JSON-serializable value.

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


jam = Jam(config="config.toml")


@dataclass
class User(BaseSubject):
    id: int
    name: str
    role: str = "user"


user = User(
    id=1,
    name="Bob",
)

token = jam.issue(
    subject=user,
    via="jwt",
    permissions=["user:read", "post:read", "post:create"]
)
```

The `id` uniquely identifies the Subject within your application. Other fields can contain any additional information needed by your application.

## Using a dictionary

A Subject can also be provided as a dictionary:

```python
token = jam.issue(
    subject={"id": 1, "name": "Bob"},
    via="jwt",
)

principal = jam.authenticate(token, via="jwt")
print(type(principal.subject))
# <class 'dict'>
```

When no typed subject class is configured, Jam preserves a dictionary as-is and
it becomes the `subject` of the resulting `Principal`.

If the Jam instance is configured with a dataclass subject type, Jam builds
that type after authentication instead:

```python
jam = Jam(config="config.toml", subject=User)

token = jam.issue(subject={"id": 1, "name": "Bob"}, via="jwt")
principal = jam.authenticate(token, via="jwt")

print(type(principal.subject))
# <class '__main__.User'>
```

Only fields declared by `User` are used to build the typed subject.

!!! tip
    Use `BaseSubject` when you want a typed Subject model. Passing a dictionary
    without configuring a subject type can be useful for simple or dynamic
    identities.

## Subject and Principal

A Subject represents an identity that **can be authenticated**.

After successful authentication, Jam represents the authenticated identity as a [`Principal`](/4.0.0/authz/principal).
