---
title: Authorization
---

Jam ships a small declarative authorization engine on top of subjects.
It answers one question: *is this subject allowed to perform this
permission?*

```python
if jam.authorize(user, "post:edit"):
    ...
```

## Policy

Class: `jam.Policy`

`Policy` maps permissions to lists of **predicates**. A permission is
granted when **any** predicate matches. **Deny by default** — permissions
that are not listed (or have no matching predicate) are denied.

Args:

* `rules`: `dict[str, list[Predicate]] | None = None` - Rules mapping
  permissions to predicate lists.

Predicate forms:

| Form | Meaning |
|------|---------|
| `"*"` | Allow every subject. |
| `"field=value"` | Allow if `subject.field == value`. |
| `"field"` | Allow if `subject.field` is truthy. |
| callable(subject) -> bool | Allow if the callable returns True. |

```python
from jam import Policy

policy = Policy(
    rules={
        "profile:read": ["*"],
        "post:create": ["is_authenticated"],
        "post:edit": ["id=42", "role=admin"],
        "admin:*": ["role=admin"],
    }
)

policy.check(user, "profile:read")  # -> True for any subject
```

The `"field=value"` predicate is evaluated with `ast.literal_eval`, so
`"id=42"`, `"role=admin"` and `"active=true"` all work.

## Configuring a policy in Jam

Add the `[jam.authz]` section to the config:

```toml
[jam.authz.rules]
"profile:read" = ["*"]
"post:create" = ["is_authenticated"]
"post:edit" = ["id=42", "role=admin"]
```

```python
from dataclasses import dataclass

from jam import BaseSubject, Jam


@dataclass
class User(BaseSubject):
    id: str
    role: str = "user"
    is_authenticated: bool = True


jam = Jam(config="config.toml", subject=User)
user = jam.authenticate(token)

print(jam.authorize(user, "post:create"))  # -> True
print(jam.authorize(user, "post:edit"))    # depends on id/role
print(jam.authorize(user, "post:delete"))  # -> False (deny by default)
```

Calling `authorize` without an `[jam.authz]` section raises
`JamConfigurationError`.

## Custom policies

Implement `jam.BasePolicy` for full control. The `module` key points to your
policy class, `rules` are passed to its constructor:

```python
from jam import BasePolicy, BaseSubject


class MyPolicy(BasePolicy):
    def __init__(self, rules: dict) -> None:
        self._rules = rules

    def check(self, subject: BaseSubject, permission: str) -> bool:
        # your logic
        return permission in self._rules.get(subject.id, [])
```

```toml
[jam.authz]
module = "my_app.policies.MyPolicy"

[jam.authz.rules]
"1" = ["profile:read", "post:create"]
```

```python
jam = Jam(config="config.toml", subject=User)
```

## Interfaces

Base class: `jam.BasePolicy`

Abstract method:

* `check(subject: BaseSubject, permission: str) -> bool` - Decide whether
  the subject may perform the permission.

Built-in implementation: `jam.Policy`.
