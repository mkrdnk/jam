# Contexts

An **Authorization Context** contains dynamic values available while Jam evaluates authorization rules.

While a [`Principal`](/4.0.0/authz/principal) represents the authenticated identity, a Context represents the circumstances under which an authorization decision is made.

```text
Principal
    │
    │ who
    ▼

Authorization

    ▲
    │
    │ under what circumstances
    │

Context
```

For example, an authorization decision may depend on:

* the current time;
* the resource being accessed;
* the current request;
* tenant information;
* environment-specific values;
* any other application-defined attributes.

## Creating a Context

```python
from jam.authz import AuthorizationContext

context = AuthorizationContext(
    resource=post,
    request=request,
    attributes={
        "tenant": "acme",
        "environment": "production",
    },
)
```

## Available fields

### `now`

The current UTC time.

```python
context.now
```

This can be used by rules that depend on time.

### `resource`

The resource for which authorization is being evaluated.

```python
context.resource
```

The resource can be any Python object.

For example:

```python
AuthorizationContext(
    resource=post,
)
```

### `request`

The current application request.

```python
context.request
```

Jam does not require a specific request type, allowing the same authorization model to be used across different frameworks.

### `attributes`

Application-defined values available during rule evaluation.

```python
AuthorizationContext(
    attributes={
        "tenant": "acme",
        "environment": "production",
    }
)
```

Attributes do not have a predefined schema. Their meaning is defined by the application.

## Using Context values in rules

Context values can be referenced from authorization rules through the `context` root.

For example:

```yaml
permissions:
  - post:update

when:
  field: context.resource.author_id
  operator: eq
  value: "@subject.id"
```

Or:

```yaml
permissions:
  - admin:access

when:
  field: context.attributes.tenant
  operator: eq
  value: acme
```

## Context and Principal

A Principal and a Context provide different information to the authorization engine.

```text
Principal
├── subject
├── claims
└── permissions

Context
├── now
├── resource
├── request
└── attributes
```

The Principal describes the authenticated identity.

The Context describes the circumstances in which authorization is evaluated.

Together they provide the data required by authorization rules.
