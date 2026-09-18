import asyncio
import base64
import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import django
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, override_settings
import pytest


if sys.version_info < (3, 11):
    pytest.skip(
        "django-modern-rest requires Python 3.11 or newer.",
        allow_module_level=True,
    )


from dmr.exceptions import NotAuthenticatedError
from dmr.response import APIError

from jam.authz import AuthorizationContext, Principal
from jam.ext import CredentialSource


if not settings.configured:
    settings.configure(
        AUTHENTICATION_BACKENDS=["jam.ext.django.JamBackend"],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            },
        },
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
        ],
        JAM_CONFIG={},
        SECRET_KEY="tests",
    )
    django.setup()


from jam.ext.django._authentication import (  # noqa: E402
    InvalidCredential,
    authenticate_request,
    detect_bearer_type,
)
from jam.ext.django.context import (  # noqa: E402
    authorization_context,
    principal_context,
)
from jam.ext.django.dmr import (  # noqa: E402
    JamAsyncAuth,
    JamSyncAuth,
    authorize,
    request_principal,
)


def _segment(value):
    raw = json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _request(*, authorization=None, session=None):
    headers = {}
    if authorization is not None:
        headers["HTTP_AUTHORIZATION"] = authorization
    if session is not None:
        headers["HTTP_COOKIE"] = f"session={session}"
    request = RequestFactory().get("/", **headers)
    request.user = SimpleNamespace(pk="django")
    return request


@pytest.mark.parametrize(
    ("credential", "expected"),
    [
        (f"{_segment({'alg': 'HS256'})}.payload.signature", "jwt"),
        (f"{_segment({'alg': 'dir', 'enc': 'A256GCM'})}.a.b.c.d", "jwe"),
        ("v4.local.payload", "paseto"),
        ("not-a-token", None),
    ],
)
def test_detect_bearer_type(credential, expected):
    assert detect_bearer_type(credential) == expected


@override_settings(
    JAM_CONFIG={
        "jose": {"jwt": {}},
        "session": {"type": "json", "path": "/tmp/sessions.json"},
    }
)
def test_bearer_has_precedence_over_session():
    request = _request(
        authorization=f"Bearer {_segment({'alg': 'HS256'})}.p.s",
        session="session-id",
    )
    bearer = Principal(SimpleNamespace(pk="bearer"), {}, "jwt")
    with patch(
        "jam.ext.django._authentication.authenticate_credential",
        return_value=bearer,
    ) as authenticate:
        assert authenticate_request(request) is bearer
    authenticate.assert_called_once()
    assert authenticate.call_args.kwargs["via"] == "jwt"


@override_settings(
    JAM_CONFIG={
        "jose": {"jwt": {}},
        "session": {"type": "json", "path": "/tmp/sessions.json"},
    }
)
def test_invalid_bearer_never_falls_back_to_session():
    request = _request(authorization="Bearer invalid", session="valid")
    with patch(
        "jam.ext.django._authentication.authenticate_credential"
    ) as authenticate:
        with pytest.raises(InvalidCredential):
            authenticate_request(request)
    authenticate.assert_not_called()


@override_settings(
    JAM_CONFIG={"session": {"type": "json", "path": "/tmp/sessions.json"}}
)
def test_session_and_missing_credentials():
    session_principal = Principal(SimpleNamespace(pk="session"), {}, "session")
    with patch(
        "jam.ext.django._authentication.authenticate_credential",
        return_value=session_principal,
    ) as authenticate:
        assert authenticate_request(_request(session="id")) is session_principal
        assert authenticate_request(_request()) is None
    authenticate.assert_called_once_with("id", via="session")


@override_settings(JAM_CONFIG={"jose": {"jwt": {}}})
def test_sync_auth_installs_request_identity():
    request = _request(
        authorization=f"Bearer {_segment({'alg': 'HS256'})}.p.s"
    )
    user = SimpleNamespace(pk="42")
    principal = Principal(user, {"permissions": ["posts.view"]}, "jwt")
    controller = SimpleNamespace(request=request)
    with patch(
        "jam.ext.django._authentication.authenticate_credential",
        return_value=principal,
    ):
        auth = JamSyncAuth()
        assert auth(None, controller) is auth
    assert request.user is user
    assert asyncio.run(request.auser()) is user
    assert request_principal(request) is principal


@override_settings(JAM_CONFIG={"session": {"type": "json"}})
@pytest.mark.asyncio
async def test_async_auth_installs_request_identity():
    request = _request(session="id")
    user = SimpleNamespace(pk="42")
    principal = Principal(user, {"request": "async"}, "session")
    controller = SimpleNamespace(request=request)
    with patch(
        "jam.ext.django._authentication.authenticate_credential_async",
        new=AsyncMock(return_value=principal),
    ):
        auth = JamAsyncAuth()
        assert await auth(None, controller) is auth
    assert request.user is await request.auser()
    assert request_principal(request) is principal


@override_settings(JAM_CONFIG={"jose": {"jwt": {}}})
def test_invalid_explicit_credential_raises_dmr_error():
    controller = SimpleNamespace(
        request=_request(authorization="Bearer invalid")
    )
    with pytest.raises(NotAuthenticatedError):
        JamSyncAuth()(None, controller)


@pytest.mark.parametrize(
    ("config", "bearer_format"),
    [
        ({"jose": {"jwt": {}}}, "JWT"),
        ({"jose": {"jwt": {"enc": "A256GCM"}}}, "JWT or JWE"),
        ({"paseto": {}}, "PASETO"),
        (
            {"jose": {"jwt": {"enc": "A256GCM"}}, "paseto": {}},
            "JWT, JWE or PASETO",
        ),
    ],
)
def test_openapi_bearer_format(config, bearer_format):
    with override_settings(JAM_CONFIG=config):
        scheme = JamSyncAuth(source="bearer").security_schemes["jamBearer"]
    assert scheme.bearer_format == bearer_format


@override_settings(JAM_CONFIG={"session": {"type": "json"}})
def test_openapi_custom_session_source():
    auth = JamSyncAuth(source=CredentialSource.header("X-Jam-Session"))
    scheme = auth.security_schemes["jamSession"]
    assert scheme.type == "apiKey"
    assert scheme.security_scheme_in == "header"
    assert scheme.name == "X-Jam-Session"
    assert auth.security_requirement == {"jamSession": []}
    assert auth.www_authenticate_challenge is None


@override_settings(
    JAM_CONFIG={
        "jose": {"jwt": {}},
        "session": {"type": "json"},
    }
)
def test_openapi_mixed_auth_uses_alternative_requirements():
    bearer = JamSyncAuth(source="bearer")
    session = JamSyncAuth(source=CredentialSource.cookie("session"))
    assert [
        bearer.security_requirement,
        session.security_requirement,
    ] == [{"jamBearer": []}, {"jamSession": []}]
    with pytest.raises(ImproperlyConfigured):
        JamSyncAuth().security_requirement


def test_authorize_uses_django_permission_api_and_cleans_context():
    principal = Principal(
        SimpleNamespace(pk="42"),
        {"permissions": ["posts.change"]},
        "jwt",
    )
    request = _request()
    request.user = principal.subject
    request._jam_principal = principal
    request.user.has_perm = Mock(return_value=True)
    original = AuthorizationContext(request="outer")
    token = authorization_context.set(original)
    try:
        assert (
            authorize(
                request,
                "posts.change",
                resource="post",
                attributes={"tenant": "one"},
            )
            is None
        )
        assert authorization_context.get() is original
        assert principal_context.get() is None
    finally:
        authorization_context.reset(token)
    request.user.has_perm.assert_called_once_with("posts.change", "post")


def test_authorize_denial_is_dmr_api_error():
    request = _request()
    request.user.has_perm = Mock(return_value=False)
    with pytest.raises(APIError) as exc_info:
        authorize(request, "posts.change")
    assert exc_info.value.status_code == 403
    assert exc_info.value.raw_data["detail"][0]["msg"] == "Permission denied."
