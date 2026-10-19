"""Django request isolation, middleware and public permission helpers."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import django
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.views import View
import pytest

if not settings.configured:
    settings.configure(
        INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes"],
        SECRET_KEY="tests",
    )
    django.setup()

from jam.authz import Principal
from jam.exceptions import JamConfigurationError, JamValidationError
from jam.ext import CredentialSource
from jam.ext.django import _authentication as auth
from jam.ext.django.context import authorization_context, principal_context
from jam.ext.django.middleware import JamMiddleware
from jam.ext.django.mixins import ObjectPermissionRequiredMixin
from jam.ext.django.drf.mixins import JamPermissionMixin
from jam.ext.django.drf.permissions import JamPermission
from jam.ext.django.templatetags.jam import jam_has_perm
from jam.ext.django.runtime import get_jam, get_async_jam

ORDER = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "jam.ext.django.JamMiddleware",
]


def request():
    result = RequestFactory().get("/")
    result.user = SimpleNamespace(pk="django", is_authenticated=True)
    return result


@pytest.mark.parametrize("order", [[], ORDER[::-1], ORDER[1:]])
def test_middleware_requires_correct_order(order):
    with (
        override_settings(MIDDLEWARE=order),
        pytest.raises(ImproperlyConfigured),
    ):
        JamMiddleware(lambda request: HttpResponse())


@pytest.mark.parametrize("failure", [False, True])
@override_settings(MIDDLEWARE=ORDER, JAM_CONFIG={})
def test_sync_middleware_context_cleanup(failure):
    req = request()
    previous = principal_context.get()
    previous_context = authorization_context.get()

    def response(current):
        assert principal_context.get().subject is req.user
        assert authorization_context.get().request is req
        if failure:
            raise RuntimeError("view failure")
        return HttpResponse("ok")

    middleware = JamMiddleware(response)
    if failure:
        with pytest.raises(RuntimeError):
            middleware(req)
    else:
        assert middleware(req).content == b"ok"
    assert principal_context.get() is previous
    assert authorization_context.get() is previous_context


@pytest.mark.asyncio
@override_settings(MIDDLEWARE=ORDER, JAM_CONFIG={})
async def test_async_middleware_isolates_concurrent_requests():
    entered = 0
    ready = asyncio.Event()

    async def response(req):
        nonlocal entered
        entered += 1
        if entered == 2:
            ready.set()
        await ready.wait()
        assert principal_context.get().subject is req.user
        assert authorization_context.get().request is req
        return HttpResponse("ok")

    middleware = JamMiddleware(response)
    a, b = request(), request()
    a.auser = AsyncMock(return_value=a.user)
    previous = principal_context.get()
    await asyncio.gather(middleware(a), middleware(b))
    assert principal_context.get() is previous
    a.auser.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@override_settings(MIDDLEWARE=ORDER, JAM_CONFIG={"jose": {"jwt": {}}})
async def test_middleware_authentication_outcomes(async_):
    async def aresponse(req):
        return HttpResponse("ok")

    response = aresponse if async_ else lambda req: HttpResponse("ok")
    method = "authenticate_request_async" if async_ else "authenticate_request"
    factory = AsyncMock if async_ else Mock
    middleware = JamMiddleware(response)

    async def invoke(req):
        result = middleware(req)
        return await result if async_ else result

    with patch(
        f"jam.ext.django.middleware.{method}",
        factory(side_effect=auth.InvalidCredential),
    ):
        result = await invoke(request())
        assert result.status_code == 401
        assert result["WWW-Authenticate"] == "Bearer"
    with patch(
        f"jam.ext.django.middleware.{method}",
        factory(side_effect=JamConfigurationError),
    ):
        with pytest.raises(JamConfigurationError):
            await invoke(request())
    principal = Principal(SimpleNamespace(pk="u"), {}, "jwt")
    req = request()
    with patch(
        f"jam.ext.django.middleware.{method}", factory(return_value=principal)
    ):
        assert (await invoke(req)).status_code == 200
    assert req.user is principal.subject
    assert await req.auser() is principal.subject


@pytest.mark.asyncio
@override_settings(MIDDLEWARE=ORDER, JAM_CONFIG={})
async def test_async_view_exception_restores_context():
    previous = principal_context.get()

    async def response(req):
        raise RuntimeError("failed")

    with pytest.raises(RuntimeError):
        await JamMiddleware(response)(request())
    assert principal_context.get() is previous


@pytest.mark.parametrize("function", [get_jam, get_async_jam])
def test_runtime_configuration_cache_and_reset(function):
    with override_settings(JAM_CONFIG={}):
        first = function()
        assert function() is first
        with override_settings(JAM_CONFIG={"application": "changed"}):
            assert function() is not first
    with (
        override_settings(JAM_CONFIG="bad"),
        pytest.raises(ImproperlyConfigured),
    ):
        function()
    with override_settings():
        if hasattr(settings, "JAM_CONFIG"):
            del settings.JAM_CONFIG
        function.cache_clear()
        with pytest.raises(ImproperlyConfigured):
            function()


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("Basic credentials", None),
        ("Bearer token", "token"),
        ("bEaReR token", "token"),
    ],
)
def test_bearer_extraction(value, expected):
    req = SimpleNamespace(
        headers={} if value is None else {"Authorization": value}
    )
    assert auth.bearer_credential(req) == expected


@pytest.mark.parametrize("value", ["Bearer", "Bearer "])
def test_empty_bearer_rejected(value):
    with pytest.raises(auth.InvalidCredential):
        auth.bearer_credential(
            SimpleNamespace(headers={"Authorization": value})
        )


@pytest.mark.parametrize(
    "source",
    [
        CredentialSource.cookie("credential"),
        CredentialSource.query("credential"),
        CredentialSource.header("credential", scheme="Token"),
    ],
)
def test_source_extraction(source):
    value = "Token secret" if source.kind == "header" else "secret"
    req = SimpleNamespace(
        headers={"credential": value},
        COOKIES={"credential": value},
        GET={"credential": value},
    )
    assert auth.source_credential(req, source) == "secret"
    req.headers["credential"] = "Wrong secret"
    if source.kind == "header":
        with pytest.raises(auth.InvalidCredential):
            auth.source_credential(req, source)


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@pytest.mark.parametrize(
    "error", [JamValidationError(), ValueError(), JamConfigurationError()]
)
async def test_credential_failure_translation(async_, error):
    method = "get_async_jam" if async_ else "get_jam"
    jam = SimpleNamespace(
        authenticate=(AsyncMock if async_ else Mock)(side_effect=error)
    )
    expected = (
        JamConfigurationError
        if isinstance(error, JamConfigurationError)
        else auth.InvalidCredential
    )
    with patch.object(auth, method, return_value=jam), pytest.raises(expected):
        if async_:
            await auth.authenticate_credential_async("token", via="jwt")
        else:
            auth.authenticate_credential("token", via="jwt")


@pytest.mark.asyncio
@override_settings(JAM_CONFIG={"session": {}})
async def test_async_request_reuses_principal_and_rejects_invalid_bearer():
    req = request()
    principal = Principal(req.user, {}, "session")
    auth.install_principal(req, principal)
    assert await auth.authenticate_request_async(req) is principal
    req = RequestFactory().get(
        "/", HTTP_AUTHORIZATION="Bearer invalid", HTTP_COOKIE="session=valid"
    )
    with pytest.raises(auth.InvalidCredential):
        await auth.authenticate_request_async(req)
    req = RequestFactory().get("/", HTTP_COOKIE="session=valid")
    with patch.object(
        auth, "authenticate_credential_async", AsyncMock(return_value=principal)
    ) as authenticate:
        assert await auth.authenticate_request_async(req) is principal
        authenticate.assert_awaited_once_with("valid", via="session")


@pytest.mark.parametrize(
    "configured,expected",
    [
        (None, ()),
        ("read", ("read",)),
        (["read", "write"], ("read", "write")),
        ({"GET": "read"}, ("read",)),
        ({"retrieve": "object"}, ("object",)),
    ],
)
def test_drf_permission_configuration(configured, expected):
    view = JamPermissionMixin()
    view.action = "retrieve"
    view.jam_permissions = configured
    view.jam_object_permissions = configured
    req = request()
    assert view.get_jam_permissions(req) == expected
    assert view.get_jam_object_permissions(req, object()) == expected


@pytest.mark.parametrize("configured", [3, b"read", ["read", 3]])
def test_drf_invalid_permission_configuration(configured):
    view = JamPermissionMixin()
    view.jam_permissions = configured
    with pytest.raises(ImproperlyConfigured):
        view.get_jam_permissions(request())


@pytest.mark.parametrize("allowed", [False, True])
def test_drf_permission_context(allowed):
    req = request()
    req.auth = Principal(req.user, {"permissions": ["read"]}, "jwt")
    view = JamPermissionMixin()
    view.jam_permissions = view.jam_object_permissions = "read"
    obj = object()
    with patch("jam.ext.django.drf.permissions.get_jam") as get:
        get.return_value.authorize.return_value = allowed
        permission = JamPermission()
        assert permission.has_permission(req, view) is allowed
        assert permission.has_object_permission(req, view, obj) is allowed
        assert get.return_value.authorize.call_args.args[2].resource is obj
    req.auth = None
    assert JamPermission().has_permission(req, object())
    assert JamPermission().has_object_permission(req, object(), obj)
    assert JamPermission._principal(req).subject is req.user


def test_object_permission_mixin_and_template_tag():
    class Protected(ObjectPermissionRequiredMixin, View):
        permission_required = "read"

        def get_permission_object(self):
            return "resource"

        def get(self, request):
            return HttpResponse("ok")

    req = request()
    req.user.has_perm = Mock(return_value=True)
    assert Protected().dispatch(req).status_code == 200
    req.user.has_perm.assert_called_with("read", "resource")
    assert jam_has_perm({"user": req.user}, "read", "resource")
    assert not jam_has_perm({"user": object()}, "read", "resource")
    req.user.has_perm.return_value = False
    with pytest.raises(PermissionDenied):
        Protected().dispatch(req)
    view = ObjectPermissionRequiredMixin()
    with pytest.raises(ImproperlyConfigured):
        view.get_permission_required()
    with pytest.raises(NotImplementedError):
        view.get_permission_object()
    view.permission_required = ["read", "write"]
    assert view.get_permission_required() == ("read", "write")


def test_django_app_validates_configuration_on_ready():
    import jam.ext.django
    from jam.ext.django.apps import JamDjangoConfig

    with override_settings(JAM_CONFIG={}):
        JamDjangoConfig("jam.ext.django", jam.ext.django).ready()
    with override_settings(JAM_CONFIG={"session": "invalid"}):
        with pytest.raises(JamConfigurationError):
            JamDjangoConfig("jam.ext.django", jam.ext.django).ready()
