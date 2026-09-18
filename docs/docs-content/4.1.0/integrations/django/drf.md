# Django REST Framework

Install the DRF extra. It includes Django, so `jamlib[django,drf]` is not
needed:

```bash
pip install "jamlib[drf]"
```

Jam uses DRF's standard authentication and permission extension points.

Before configuring DRF, complete the base
[Django setup](/4.1.0/integrations/django/django): define `JAM_CONFIG` and add
`"jam.ext.django"` to `INSTALLED_APPS`.
`JamMiddleware` is optional for DRF-only applications.

## Authentication

Configure the authenticator globally or per view:

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "jam.ext.django.drf.JamAuthentication",
    ],
}
```

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from jam.ext.django.drf import (
    JamAuthentication,
    JamPermission,
    JamPermissionMixin,
)


class ProfileView(JamPermissionMixin, APIView):
    authentication_classes = [JamAuthentication]
    permission_classes = [IsAuthenticated, JamPermission]
    jam_permissions = {"GET": "profiles:read"}

    def get(self, request):
        return {
            "user": request.user.pk,
            "permissions": list(request.auth.permissions),
        }
```

`request.user` is the configured `AUTH_USER_MODEL`; `request.auth` is a Jam
`Principal`, and `request.auth.subject == request.user`. JWT and PASETO Bearer
credentials are detected and verified by the same Django adapter used by
`JamMiddleware`.

An absent or non-Bearer `Authorization` header returns `None`, allowing another
DRF authenticator to run. An explicitly supplied invalid Bearer credential
returns `401` with `WWW-Authenticate: Bearer` and does not fall back:

```python
from rest_framework.authentication import SessionAuthentication

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "jam.ext.django.drf.JamAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
}
```

`JamMiddleware` is not required. When it is present for regular Django views,
the DRF adapter reuses its token principal instead of verifying the credential
again.

## Jam-native permissions

Use `JamPermission` with `JamPermissionMixin` for Jam permission names. Jam
receives the full `Principal` and DRF `Request`. `JamPermission` authorizes
configured permissions; it does not require an authenticated user by itself.
Combine it with `IsAuthenticated` unless anonymous access is intentional:

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from jam.ext.django.drf import JamPermission, JamPermissionMixin


class ReportView(JamPermissionMixin, APIView):
    permission_classes = [IsAuthenticated, JamPermission]
    jam_permissions = {
        "GET": "reports:read",
        "POST": ("reports:read", "reports:export"),
    }
```

All listed permissions must be allowed. A mapping first resolves a ViewSet's
`action`, then falls back to the HTTP method. This supports built-in and custom
`@action` actions. An action or method absent from the mapping has no Jam
permission requirement, so configure every protected operation explicitly:

```python
class PostViewSet(JamPermissionMixin, ModelViewSet):
    permission_classes = [IsAuthenticated, JamPermission]
    jam_permissions = {
        "list": "posts:list",
        "create": "posts:create",
    }
    jam_object_permissions = {
        "retrieve": "posts:view",
        "update": "posts:edit",
        "partial_update": "posts:edit",
        "destroy": "posts:delete",
        "publish": "posts:publish",
    }
```

Request-level checks receive `AuthorizationContext(request=request)`.
Object-level checks receive `AuthorizationContext(request=request,
resource=obj)`, and are performed by DRF when the view calls `get_object()`.
Override `get_jam_permissions(request)` or
`get_jam_object_permissions(request, obj)` for dynamic configuration.
For custom views that obtain objects without `get_object()`, call
`check_object_permissions(request, obj)` yourself.

DRF does not run object-permission checks for every item in a list response.
Restrict `get_queryset()` or add a filter backend when a list must contain
only objects the subject may view.

## Django permission classes

`DjangoModelPermissions` and `DjangoObjectPermissions` remain supported and
are a separate integration path:

```python
from rest_framework.permissions import DjangoModelPermissions


class PostViewSet(ModelViewSet):
    permission_classes = [DjangoModelPermissions]
```

They use Django permission names through `request.user.has_perm()`, so include
`"jam.ext.django.JamBackend"` in `AUTHENTICATION_BACKENDS`. In contrast,
`JamPermission` calls `get_jam().authorize()` directly with the principal,
claims, DRF request, and optional resource.
