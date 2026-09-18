# Django

Install Django support:

```bash
pip install "jamlib[django]"
```

Jam integrates with Django's existing authentication and permission APIs. Add
the application, retain Django's normal session middleware, and add one Jam
middleware immediately after Django authentication:

```python
INSTALLED_APPS = [
    # ...
    "jam.ext.django",
]

MIDDLEWARE = [
    # ...
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "jam.ext.django.JamMiddleware",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "jam.ext.django.JamBackend",
]

JAM_CONFIG = {
    # ordinary Jam configuration
}
```

`JAM_CONFIG` is required. The app validates it during Django startup. Jam is
created once per process; `get_jam()` is available when direct access is
necessary, but application code normally uses Django APIs. Configure at least
the token module that the application will issue and accept. For example:

```python
import os


JAM_CONFIG = {
    "jose": {
        "jwt": {
            "alg": "HS256",
            "secret_key": os.environ["JAM_JWT_SECRET"],
        },
    },
}
```

See [Configuration](/latest/gettingstarted/configuration) for all available
modules and options.

## Sessions and permissions

Django sessions, `authenticate()`, `login()`, and `logout()` are unchanged.
Jam authorization participates through `JamBackend`, so standard Django
decorators and mixins continue to be the public interface:

```python
from django.contrib.auth.decorators import login_required, permission_required


@login_required
def profile(request):
    return render(request, "profile.html")


@permission_required("posts.change_post", raise_exception=True)
def edit_post(request, post_id):
    ...
```

Use object permissions through Django too:

```python
if request.user.has_perm("posts.change_post", post):
    ...
```

The object is exposed to Jam policies as `context.resource`; the current
request is `context.request`. This also works outside a request, where the
context simply has no request.

`ModelBackend` and `JamBackend` can be installed together as above: Django's
normal backend aggregation allows either backend to grant a permission. This
means a Django model or group permission can grant access without a Jam policy
grant. Keep both backends only when that is intentional. To use Jam as the
only authorization source, configure:

```python
AUTHENTICATION_BACKENDS = ["jam.ext.django.JamBackend"]
```

## Class-based views and templates

`PermissionRequiredMixin` works without a Jam-specific replacement. For an
object permission, use the one additional mixin Django does not provide:

```python
from jam.ext.django import ObjectPermissionRequiredMixin


class EditPostView(ObjectPermissionRequiredMixin, UpdateView):
    permission_required = "posts.change_post"

    def get_permission_object(self):
        return self.get_object()
```

Non-object checks work with Django's built-in `perms` template variable. Load
the Jam tag for object checks:

```django
{% load jam %}
{% jam_has_perm "posts.change_post" post as can_edit %}
{% if can_edit %}<a href="...">Edit</a>{% endif %}
```

## Jam credential authentication

`JamMiddleware` accepts JWT, compact JWE, and PASETO credentials from the
standard `Authorization: Bearer ...` header. When the `session` module is
configured, it also accepts a Jam Session from the `session` cookie. The token
or session subject must be the primary key of a Django user. The resolved
`AUTH_USER_MODEL` instance becomes `request.user`, including for custom user
models and custom primary keys.

```python
from jam.ext.django import get_jam


token = get_jam().issue(
    subject={"id": user.pk},
    via="jwt",
    permissions=["posts.change_post"],
)
```

The authenticated credential's claims remain available to Jam authorization,
while Django code always sees the Django user object. The same issuance
approach works with `via="paseto"`. Configure JWT encryption to issue and
accept compact JWE credentials.

Jam resolves the token subject with
`AUTH_USER_MODEL._default_manager.get(pk=subject)`. A Bearer credential does
not create or update a Django user; its subject must identify an existing
user. In a policy, `Principal.subject` is that user, while
`Principal.claims` contains the token claims. `context.request` contains the
current request and `context.resource` contains the object passed to
`user.has_perm(permission, obj)`.

### Jam Session source

Jam Session credentials use `Cookie: session=<session-id>` by default. This is
not a Django session: it is verified with `Jam.authenticate(...,
via="session")`. It is enabled only when the `session` module is present in
`JAM_CONFIG`.

Authentication precedence is deliberate:

* valid Bearer credential: it replaces a Jam or Django session identity;
* invalid Bearer credential: return `401` with `WWW-Authenticate: Bearer`; do
  not fall back;
* no Bearer and valid Jam Session: it replaces the Django session identity;
* invalid Jam Session: return `401`; do not fall back to the Django session;
* no Jam credential: retain the normal Django session (or anonymous) user.

Both synchronous and asynchronous Django views are supported. In a
Jam-authenticated async view, `request.user` and `await request.auser()`
refer to the same Django user.
