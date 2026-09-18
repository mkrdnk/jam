# Rules

`Jam.authorize()` evaluates a permission against the authenticated
`Principal`, an optional `AuthorizationContext`, and the policy configured for
the Jam instance.

```python
allowed = jam.authorize(principal, "post:edit", context)
```

Authorization is deny-by-default: a permission is denied when no matching
grant or allow rule permits it.

## `Policy`

`Policy` is Jam's built-in implementation of `BasePolicy`. `Jam` creates it
from `authz.rules` unless the configuration selects a custom policy class.

```python
from jam import Policy

policy = Policy(
    {
        "report:read": ["role=analyst"],
        "report:export": ["role=admin"],
    }
)

policy.check(
    {"id": "42", "role": "analyst"},
    "report:read",
)
# True
```

### Constructor

```python
Policy(rules=None, **kwargs)
```

`rules` accepts either a compact permission mapping or a sequence of structured
rules. `kwargs` is accepted for configuration compatibility and is ignored by
the built-in policy.

### `check()`

```python
policy.check(principal, permission, context=None)
```

| Argument | Accepted values | Description |
| --- | --- | --- |
| `principal` | `Principal`, `BaseSubject`, or `dict` | The authenticated identity. A subject or dictionary is wrapped in a Principal without credential claims. |
| `permission` | Non-empty string | The requested permission, for example `report:read`. |
| `context` | `AuthorizationContext` or `None` | Dynamic request data. When omitted, Jam creates an empty context with the current UTC time. |

`check()` returns `True` when access is allowed and `False` when it is denied.
An empty or non-string permission is a configuration error.

### Decision order

For every `check()` call, `Policy` evaluates access in this order:

1. Find rules whose permission pattern matches the requested permission.
2. If a credential declares `permissions` or `scope` but does not grant the
   requested permission, deny immediately.
3. Evaluate all matching deny rules. Any matching deny rule denies access.
4. Evaluate matching allow rules. Access is allowed if at least one condition
   matches.
5. If no allow rule matches, allow only when the credential itself grants the
   permission; otherwise deny.

This order means that a server-side policy can restrict a token but cannot add
an undeclared permission to a token that explicitly lists its grants.

## Configure a policy

Pass rules under `authz.rules` when constructing `Jam`:

```python
from jam import Jam

jam = Jam(
    config={
        "authz": {
            "rules": {
                "post:read": ["*"],
                "post:edit": ["role=editor", "role=admin"],
            }
        }
    }
)
```

The compact form maps each permission pattern to a list of predicates. The
predicates use **OR** semantics: any matching predicate allows the permission.

* `"*"` matches every subject.
* `"role=editor"` compares a subject field with a value.
* `"active"` requires a truthy subject field.

Compact predicates only read subject data. They cannot access private names or
call methods.

## Structured rules

Use structured rules when a decision depends on the token or request context:

```python
from jam import Policy

policy = Policy(
    [
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

A structured rule has:

| Field | Description |
| --- | --- |
| `effect` | `"allow"` (default) or `"deny"` |
| `permissions` | One or more permissions or wildcard patterns |
| `when` | Optional condition; omitted means the rule always matches |

Matching deny rules always take precedence over matching allow rules.

## Permissions from credentials

Pass `permissions` to `Jam.issue()` to grant permissions to one credential:

```python
token = jam.issue(
    subject=user,
    via="jwt",
    permissions=["post:read", "post:edit"],
)
```

`Principal.permissions` reads the `permissions` claim, or the `scope` claim
when `permissions` is absent. A string `scope` is split on whitespace.

Credential grants support:

* an exact permission, such as `post:edit`;
* a namespace wildcard, such as `post:*`;
* the global wildcard `*`.

When a credential explicitly declares `permissions` or `scope`, it cannot gain
a permission absent from those grants, even if an allow rule matches. A
credential with no declared grants can be authorized by a matching policy rule.

## Conditions

Structured conditions read fields from one of three roots:

| Root | Values |
| --- | --- |
| `subject` | Fields of the authenticated subject |
| `token` | Credential claims |
| `context` | `time`/`now`, `resource`, `request`, and `attributes` |

The `field` value must start with one of these roots. Paths use dot notation,
for example `subject.role` or `context.request.ip`. Every path component must
be a public Python identifier: private names, missing fields, and methods
cannot be read by a rule.

```python
{
    "field": "subject.role",
    "operator": "eq",
    "value": "editor",
}
```

## Comparing fields with `@`

Most conditions compare a field with a literal `value`. Prefix `value` with
`@` to resolve it as a second field path instead. This is useful when the
expected value is only known for the current request, resource, or subject.

```python
{
    "field": "context.resource.author_id",
    "operator": "eq",
    "value": "@subject.id",
}
```

Here `@subject.id` means “read the `id` of the authenticated subject,” not the
literal string `"@subject.id"`. The reference may use any root:

```python
{
    "field": "token.tenant",
    "operator": "eq",
    "value": "@context.attributes.tenant",
}
```

An `@` reference must be a valid public path with a root. If the referenced
value does not exist, policy evaluation raises a configuration error rather
than silently granting access.

## Combine conditions

Use exactly one logical key per condition:

| Key | Value | Result |
| --- | --- | --- |
| `all` | A list of conditions | Every condition must match |
| `any` | A list of conditions | At least one condition must match |
| `not` | One condition | Inverts the nested condition |

For example, an administrator may edit a post unless the request comes from a
blocked network:

```python
{
    "all": [
        {
            "field": "subject.role",
            "operator": "eq",
            "value": "admin",
        },
        {
            "not": {
                "field": "context.request.ip",
                "operator": "ip_in_network",
                "value": "198.51.100.0/24",
            }
        },
    ]
}
```

## Comparison operators

The default operator is `eq`. An unavailable field evaluates to `False` for
all operators except `exists`. Type mismatches, invalid IP addresses, and
incomparable values also evaluate to `False`. An invalid regular expression is
a configuration error when the policy is created.

### Presence and equality

| Operator | Meaning | Example |
| --- | --- | --- |
| `exists` | Field is present when `value` is `True`; absent when `value` is `False` | `{"field": "token.email", "operator": "exists", "value": True}` |
| `truthy` | Python truthiness of the field; `value` is ignored | `{"field": "subject.active", "operator": "truthy"}` |
| `eq` | Field equals `value` | `{"field": "subject.role", "operator": "eq", "value": "admin"}` |
| `ne` | Field differs from `value` | `{"field": "subject.status", "operator": "ne", "value": "blocked"}` |

### Membership and strings

| Operator | Meaning | Example |
| --- | --- | --- |
| `in` | Field is an item in `value` | `{"field": "subject.role", "operator": "in", "value": ["editor", "admin"]}` |
| `not_in` | Field is not an item in `value` | `{"field": "subject.role", "operator": "not_in", "value": ["blocked"]}` |
| `contains` | Field contains `value` | `{"field": "token.groups", "operator": "contains", "value": "operators"}` |
| `contains_any` | Field contains at least one item from `value` | `{"field": "token.groups", "operator": "contains_any", "value": ["operators", "admins"]}` |
| `contains_all` | Field contains every item from `value` | `{"field": "token.groups", "operator": "contains_all", "value": ["operators", "admins"]}` |
| `starts_with` | String field starts with `value` | `{"field": "subject.email", "operator": "starts_with", "value": "admin@"}` |
| `ends_with` | String field ends with `value` | `{"field": "subject.email", "operator": "ends_with", "value": "@example.com"}` |
| `matches` | String field fully matches the regular expression in `value` | `{"field": "subject.role", "operator": "matches", "value": "[aA]dmin"}` |

`matches` uses a full match, not a substring search. For example, `admin` does
not match `superadmin`; use `.*admin.*` when a substring match is intended.

### IP addresses and networks

Use `ip_in_network` to restrict an action to an IPv4 or IPv6 network. The
field must resolve to an address accepted by Python's `ipaddress` module, and
the value must be a CIDR network.

```python
{
    "field": "context.request.ip",
    "operator": "ip_in_network",
    "value": "192.0.2.0/24",
}
```

This condition is `True` for `192.0.2.42` and `False` for `198.51.100.42`.
Malformed addresses and networks deny the condition rather than raising during
evaluation.

To deny a network, use a deny rule or wrap the condition in `not`:

```python
{
    "not": {
        "field": "context.request.ip",
        "operator": "ip_in_network",
        "value": "198.51.100.0/24",
    }
}
```

### Ranges and ordering

| Operator | Meaning |
| --- | --- |
| `between` | Field is between the two values in `value`, inclusive |
| `gt`, `gte` | Field is greater than, or greater than or equal to, `value` |
| `lt`, `lte` | Field is less than, or less than or equal to, `value` |

`between` requires exactly two values:

```python
{
    "field": "context.attributes.risk_score",
    "operator": "between",
    "value": [0, 50],
}
```

For a `datetime` field, two string values in `between` are interpreted as
ISO-8601 times. The start is inclusive and the end is exclusive; a range may
cross midnight:

```python
{
    "field": "context.now",
    "operator": "between",
    "value": ["09:00:00", "18:00:00"],
    "timezone": "Europe/Berlin",
}
```

`timezone` must be a valid IANA timezone name. It is used only when the field
being compared is a `datetime`.

See [Contexts](./context) for constructing an `AuthorizationContext`.
