---
title: Authorization
---

Jam combines permissions granted to one credential with server-side policy
rules. This makes it possible to issue two tokens for the same user with
different permissions and to restrict those permissions using the current
time, resource or request.

```python
principal = jam.authenticate(token)

if jam.authorize(principal, "user:delete"):
    ...
```

Authorization is deny by default. A matching `deny` rule always takes
precedence over `allow`.

## Credential permissions

Pass permissions when issuing a JWT, PASETO or session:

```python
token = jam.issue(
    user,
    permissions=["profile:read", "user:delete"],
    exp=3600,
)
```

Permissions are stored in the credential claims. `authenticate` returns a
`Principal` containing both the reconstructed subject and all credential
claims:

```python
principal = jam.authenticate(token)

print(principal.subject.id)
print(principal.permissions)
print(principal.token_type)
```

For JWT credentials, `principal.jti` exposes the optional JWT ID claim.

A credential grant can be exact (`user:delete`), namespaced (`user:*`) or
global (`*`). Wildcards only match complete permission namespaces:
`user:*` matches `user:read` and `user:delete`, but not `admin:delete`.

When a credential contains a `permissions` or OAuth-style `scope` claim, its
grants form an upper bound: a server policy cannot add a permission absent
from that credential.

Permissions in a signed JWT or PASETO cannot be changed after issue. Issue a
new credential to change them. Stateful per-token changes require a grant
store with a format-independent credential identifier; that is not part of
the current stateless policy engine.

## Structured policy rules

Structured rules define an effect, one or more permissions and an optional
condition:

```python
from jam import Policy


policy = Policy(
    rules=[
        {
            "effect": "allow",
            "permissions": ["post:edit"],
            "when": {
                "field": "subject.role",
                "operator": "eq",
                "value": "editor",
            },
        },
        {
            "effect": "deny",
            "permissions": ["post:edit"],
            "when": {
                "field": "context.resource.locked",
                "operator": "eq",
                "value": True,
            },
        },
    ]
)
```

Rules can address three data roots:

| Root | Contents |
|------|----------|
| `subject.*` | Authenticated subject fields. |
| `token.*` | Credential claims such as `jti`, `iss` and `permissions`. |
| `context.*` | Current time, resource, request and application attributes. |

Only mapping keys and dataclass fields are accessible. Methods, private
attributes and arbitrary Python object attributes are not evaluated.

### TOML configuration

```toml
[[jam.authz.rules]]
effect = "allow"
permissions = ["user:delete"]

[jam.authz.rules.when]
all = [
  { field = "subject.active", operator = "eq", value = true },
  { field = "context.time", operator = "between", value = ["17:00", "18:00"], timezone = "Europe/Moscow" },
]

[[jam.authz.rules]]
effect = "deny"
permissions = ["user:delete"]

[jam.authz.rules.when]
field = "context.resource.protected"
operator = "eq"
value = true
```

This allows `user:delete` only for active subjects from 17:00 inclusive until
18:00 exclusive in the configured timezone. A protected resource is always
denied.

## Authorization context

Dynamic values are supplied for each decision:

```python
from datetime import datetime, timezone

from jam import AuthorizationContext


context = AuthorizationContext(
    now=datetime.now(timezone.utc),
    resource=target_user,
    request={"ip": "192.0.2.10"},
    attributes={"tenant": "example"},
)

allowed = jam.authorize(principal, "user:delete", context)
```

`AuthorizationContext.now` defaults to the current UTC time. Pass it
explicitly in tests and whenever the application owns the clock.

Available paths include:

```text
context.time
context.now
context.resource.*
context.request.*
context.attributes.*
```

`resource` and `request` should be mappings or dataclass instances when their
fields are used by declarative rules.

## Logical conditions

Conditions can be composed with `all`, `any` and `not`:

```python
{
    "all": [
        {
            "field": "subject.active",
            "operator": "eq",
            "value": True,
        },
        {
            "any": [
                {
                    "field": "subject.role",
                    "operator": "eq",
                    "value": "admin",
                },
                {
                    "field": "token.permissions",
                    "operator": "contains",
                    "value": "user:delete",
                },
            ]
        },
    ]
}
```

## Operators

| Group | Operators |
|-------|-----------|
| Presence | `exists`, `truthy` |
| Equality | `eq`, `ne` |
| Ordering | `gt`, `gte`, `lt`, `lte`, `between` |
| Collections | `in`, `not_in`, `contains`, `contains_any`, `contains_all` |
| Strings | `starts_with`, `ends_with`, `matches` |
| Networks | `ip_in_network` |

For a datetime field, `between` accepts two ISO times. The interval is
start-inclusive and end-exclusive and supports ranges crossing midnight:

```python
{
    "field": "context.time",
    "operator": "between",
    "value": ["22:00", "06:00"],
    "timezone": "UTC",
}
```

`matches` uses a full regular-expression match.

## Compact policy syntax

For simple policies, use the compact syntax:

```toml
[jam.authz.rules]
"profile:read" = ["*"]
"post:create" = ["is_authenticated"]
"post:edit" = ["id='42'", "role=admin"]
"admin:*" = ["role=admin"]
```

Predicates inside one list use `OR` semantics:

| Form | Meaning |
|------|---------|
| `"*"` | Match every subject. |
| `"field=value"` | Compare a subject field with a scalar value. |
| `"field"` | Check that a subject field is truthy. |
| callable | Call a Python predicate in a directly constructed `Policy`. |

Lowercase `true`, `false` and `null` are supported. Quote numeric-looking
string identifiers, for example `id='42'`; unquoted `id=42` compares with an
integer.

Use structured rules when a permission needs `AND`, `NOT`, deny rules, token
claims or request-time context.

## Custom policies

Implement `BasePolicy` for a different policy engine:

```python
from jam import AuthorizationContext, BasePolicy, Principal


class MyPolicy(BasePolicy):
    def __init__(self, rules: dict) -> None:
        self._rules = rules

    def check(
        self,
        principal: Principal,
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        return permission in self._rules.get(principal.subject.id, [])
```

Configure its import path:

```toml
[jam.authz]
module = "my_app.policies.MyPolicy"

[jam.authz.rules]
"1" = ["profile:read", "post:create"]
```
