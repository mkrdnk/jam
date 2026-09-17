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
necessary, but application code normally uses Django APIs.

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
normal backend aggregation allows either backend to grant a permission. To use
only Jam authorization, configure:

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

## JWT and PASETO Bearer authentication

`JamMiddleware` accepts JWT and PASETO credentials from the standard
`Authorization: Bearer ...` header. The token subject must be the primary key
of a Django user. The resolved `AUTH_USER_MODEL` instance becomes
`request.user`, including for custom user models and custom primary keys.

```python
token = get_jam().issue(
    subject={"id": user.pk},
    via="jwt",
    permissions=["posts.change_post"],
)
```

The authenticated token's claims remain available to Jam authorization, while
Django code always sees the Django user object. The same issuance approach
works with `via="paseto"`.

Authentication precedence is deliberate:

* no Bearer header: retain the normal session (or anonymous) user;
* valid Bearer header: it replaces any session identity;
* malformed, invalid, expired, or unknown-user Bearer header: return `401`
  with `WWW-Authenticate: Bearer`; do not fall back to the session.

Both synchronous and asynchronous Django views are supported. In a
Bearer-authenticated async view, `request.user` and `await request.auser()`
refer to the same Django user.
