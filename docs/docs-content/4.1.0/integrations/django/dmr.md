# Django Modern REST

Install the DMR extra. It includes Django support, so
`jamlib[django,dmr]` is not needed. Python 3.11 or newer is required:

```bash
pip install "jamlib[dmr]"
```

Jam uses DMR's standard authentication extension points and Django's standard
user and permission APIs. It does not introduce a separate request, user
model, or permission DSL.

## Setup

Complete the base [Django setup](/4.1.0/integrations/django/django): define
`JAM_CONFIG`, add `"jam.ext.django"` to `INSTALLED_APPS`, and configure
`JamBackend` when Django permission APIs should use Jam policies.

Configure DMR's sync and async authenticators:

```python
from dmr.security import SyncOrAsyncAuth
from dmr.settings import Settings

from jam.ext.django.dmr import JamAsyncAuth, JamSyncAuth


DMR_SETTINGS = {
    Settings.auth: [
        SyncOrAsyncAuth(
            JamSyncAuth(),
            JamAsyncAuth(),
        ),
    ],
}
```

`JAM_CONFIG` enables the supported credential mechanisms. Auth instances are
stateless and can be safely configured globally.

`JamMiddleware` is optional for DMR-only applications. When it is installed
for regular Django views, DMR reuses the verified principal instead of
verifying the credential again.

## Authentication

`JamSyncAuth` and `JamAsyncAuth` support all configured Jam credentials:

| `JAM_CONFIG` entry | Transport | Principal `token_type` |
| --- | --- | --- |
| `jose.jwt` | `Authorization: Bearer` | `jwt` |
| encrypted `jose.jwt` | `Authorization: Bearer` | `jwe` |
| `paseto` | `Authorization: Bearer` | `paseto` |
| `session` | `Cookie: session=...` by default | `session` |

JWT, compact JWE, and PASETO are detected before verification and are
authenticated through the matching `Jam.authenticate()` mechanism. Bearer
credentials use the standard header:

```http
Authorization: Bearer <credential>
```

The token or session subject must be the primary key of a Django user. The
resolved `AUTH_USER_MODEL` instance becomes `request.user`, including for
custom user models and custom primary keys:

```python
from dmr import Controller


class ProfileController(Controller):
    def get(self):
        return {"user_id": self.request.user.pk}
```

In an async controller, `request.user` and `await request.auser()` refer to
the same user.

Use `request_principal()` when application code also needs Jam claims:

```python
from dmr import Controller

from jam.ext.django.dmr import request_principal


class ProfileController(Controller):
    def get(self):
        principal = request_principal(self.request)
        return {
            "user_id": self.request.user.pk,
            "permissions": list(principal.permissions),
        }
```

The returned Principal preserves all credential claims and satisfies
`principal.subject == request.user`.

### Jam Session source

Jam Session authentication uses the `session` cookie by default:

```http
Cookie: session=<session-id>
```

Change it with the existing `CredentialSource` API:

```python
from jam.ext.django.dmr import CredentialSource, JamSyncAuth


auth = JamSyncAuth(
    session_source=CredentialSource.cookie("jam_session"),
)

header_auth = JamSyncAuth(
    session_source=CredentialSource.header("X-Jam-Session"),
)
```

Cookie, header, and query sources are supported. This is a Jam Session,
verified with `Jam.authenticate(..., via="session")`; it is not a Django
Session.

### Django Session authentication

Use DMR's own Django Session authenticator after Jam auth when an endpoint
accepts both identity systems:

```python
from dmr.security.django_session import DjangoSessionSyncAuth

from jam.ext.django.dmr import JamSyncAuth


auth = (
    JamSyncAuth(),
    DjangoSessionSyncAuth(),
)
```

Use `DjangoSessionAsyncAuth` with `JamAsyncAuth` for async controllers.

Credential precedence is deliberate:

* valid Bearer credential: use its identity, even if a Jam Session is present;
* invalid Bearer credential: return `401`; do not try Jam or Django Session;
* no Bearer and valid Jam Session: use the Jam Session identity;
* invalid Jam Session: return `401`; do not try Django Session;
* no Jam credential: return `None` and continue the DMR auth chain.

In short, an explicitly supplied invalid credential never triggers fallback.

## Django permissions

Use Django's standard permission API. `JamBackend` passes the current
Principal, request, and optional resource to `Jam.authorize()`:

```python
if self.request.user.has_perm("posts.change_post", post):
    ...
```

`ModelBackend` and `JamBackend` can be installed together: Django allows
either backend to grant permission. To use only Jam authorization, configure:

```python
AUTHENTICATION_BACKENDS = ["jam.ext.django.JamBackend"]
```

Use `authorize()` when denial should immediately become a DMR JSON `403`
response:

```python
from jam.ext.django.dmr import authorize


authorize(
    self.request,
    "posts.change_post",
    resource=post,
    attributes={
        "tenant": tenant,
        "workspace": workspace,
    },
)
```

The message is `Permission denied.`. Additional attributes are available to
Jam policies as `context.attributes`; the resource is `context.resource`.
The temporary authorization context is always restored.

## Declarative permissions

DMR controllers are Django views, so use Django's standard
`permission_required()` decorator through DMR's decorator adapters:

```python
from django.contrib.auth.decorators import permission_required
from dmr import Controller, dispatch_decorator, endpoint_decorator


@dispatch_decorator(
    permission_required("posts.view_post", raise_exception=True),
)
class PostsController(Controller):
    @endpoint_decorator(
        permission_required("posts.add_post", raise_exception=True),
    )
    def post(self):
        ...
```

Use `dispatch_decorator()` for the whole controller and
`endpoint_decorator()` for one endpoint. Both forms use `JamBackend`.

For object permissions, call `request.user.has_perm(permission, obj)` or
reuse `jam.ext.django.ObjectPermissionRequiredMixin`. A DMR-specific mixin is
not required.

## OpenAPI

Authentication schemes are derived from `JAM_CONFIG`:

* JWT, JWE, or PASETO creates the `jamBearer` HTTP Bearer scheme;
* `bearerFormat` lists the enabled Bearer credential formats;
* Jam Session creates the `jamSession` API key scheme with its configured
  cookie, header, or query parameter name;
* a Session-only configuration does not create a fake Bearer scheme.

DMR 0.15 allows one OpenAPI Security Requirement object per auth instance.
Putting Bearer and Session in that object would incorrectly mean Bearer AND
Session. For a mixed configuration, use two instances of the same public Jam
auth classes so DMR publishes Bearer OR Session:

```python
from dmr.security import SyncOrAsyncAuth
from dmr.settings import Settings

from jam.ext.django.dmr import (
    CredentialSource,
    JamAsyncAuth,
    JamSyncAuth,
)


DMR_SETTINGS = {
    Settings.auth: [
        SyncOrAsyncAuth(
            JamSyncAuth(source="bearer"),
            JamAsyncAuth(source="bearer"),
        ),
        SyncOrAsyncAuth(
            JamSyncAuth(source=CredentialSource.cookie("session")),
            JamAsyncAuth(source=CredentialSource.cookie("session")),
        ),
    ],
}
```

Bearer-capable instances advertise `WWW-Authenticate: Bearer`. Session-only
instances do not advertise a challenge because their credentials are not
sent through `Authorization`.
