---
title: Subjects
---

A **subject** is the entity that performs authentication and authorization —
typically a user. In Jam, subjects are dataclasses inheriting from
`jam.BaseSubject`.

```python
from dataclasses import dataclass

from jam import BaseSubject


@dataclass
class User(BaseSubject):
    id: str
    email: str = ""
    role: str = "user"
```

## Contract

* The class must be a **dataclass**.
* It must declare an **`id`** field. Subclasses without an `id` raise a
  `TypeError` at class creation.
* Serialization is built on `dataclasses`, no extra dependencies.

## Serialization

Method: `subject.to_dict`

Serializes the subject with `dataclasses.asdict`.

Returns:

`dict[str, Any]` - Subject fields.

```python
user = User(id="1", email="user@example.com", role="admin")
print(user.to_dict())
>>> {'id': '1', 'email': 'user@example.com', 'role': 'admin'}
```

Classmethod: `BaseSubject.from_dict`

Builds a subject from a dict. Unknown keys are ignored.

Args:

* `data`: `dict[str, Any]` - Subject fields.

Returns:

`BaseSubject` - New subject instance.

```python
user = User.from_dict({"id": "1", "email": "user@example.com", "extra": 1})
print(user.id)     # -> "1"
print(user.email)  # -> "user@example.com"
```

## Subjects in Jam

Pass the subject class to `Jam` and it will be used by `authenticate` to
build typed results:

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class User(BaseSubject):
    id: str
    email: str = ""


jam = Jam(config="config.toml", subject=User)

token = jam.issue(User(id="1", email="user@example.com"), via="jwt")
principal = jam.authenticate(token, via="jwt")
user = principal.subject

print(type(user))  # -> <class '__main__.User'>
```

Without a subject class (or when `subject` is not a dataclass),
`principal.subject` contains the payload mapping. `principal.claims` always
contains the complete verified claims.

You can also pass a plain dict with an `"id"` key to `issue` — the `id`
becomes the `sub` claim.
