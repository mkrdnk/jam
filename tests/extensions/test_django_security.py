import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import django
from django.conf import settings
import pytest


if not settings.configured:
    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
        ],
        SECRET_KEY="tests",
    )
    django.setup()


from jam.authz import Principal
from jam.ext.django._authentication import (  # noqa: E402
    InvalidCredential,
    authenticate_credential,
    authenticate_credential_async,
    install_principal,
)
from jam.ext.django.backends import JamBackend  # noqa: E402
from jam.ext.django.context import principal_context  # noqa: E402


def _user_model(user):
    return SimpleNamespace(
        _default_manager=SimpleNamespace(
            get=Mock(return_value=user),
            aget=AsyncMock(return_value=user),
        )
    )


def test_inactive_user_cannot_authenticate_with_credential():
    """Неактивный пользователь не проходит синхронную аутентификацию."""
    user = SimpleNamespace(pk="42", is_active=False)
    principal = Principal({"id": user.pk}, {}, "jwt")
    jam = SimpleNamespace(authenticate=Mock(return_value=principal))

    with (
        patch("jam.ext.django._authentication.get_jam", return_value=jam),
        patch(
            "jam.ext.django._authentication.get_user_model",
            return_value=_user_model(user),
        ),
        pytest.raises(InvalidCredential),
    ):
        authenticate_credential("credential", via="jwt")


def test_inactive_user_cannot_authenticate_with_async_credential():
    """Неактивный пользователь не проходит асинхронную аутентификацию."""
    user = SimpleNamespace(pk="42", is_active=False)
    principal = Principal({"id": user.pk}, {}, "jwt")
    jam = SimpleNamespace(authenticate=AsyncMock(return_value=principal))

    with (
        patch(
            "jam.ext.django._authentication.get_async_jam",
            return_value=jam,
        ),
        patch(
            "jam.ext.django._authentication.get_user_model",
            return_value=_user_model(user),
        ),
        pytest.raises(InvalidCredential),
    ):
        asyncio.run(authenticate_credential_async("credential", via="jwt"))


def test_install_principal_keeps_credential_state_on_request():
    """Principal credential остаётся на request, но не на модели пользователя."""
    user = SimpleNamespace(pk="42")
    principal = Principal(user, {"scope": "write"}, "jwt")
    request = SimpleNamespace()

    install_principal(request, principal)

    assert request._jam_principal is principal
    assert not hasattr(user, "_jam_principal")


def test_backend_ignores_principal_stored_on_user():
    """Backend не использует claims, сохранённые на экземпляре пользователя."""
    user = SimpleNamespace(pk="42")
    user._jam_principal = Principal(user, {"scope": "write"}, "jwt")
    authorize = Mock(return_value=True)

    with patch(
        "jam.ext.django.backends.get_jam",
        return_value=SimpleNamespace(authorize=authorize),
    ):
        assert JamBackend().has_perm(user, "reports:read")

    principal = authorize.call_args.args[0]
    assert principal.subject is user
    assert principal.claims == {}
    assert principal.token_type == "django"


def test_backend_uses_request_local_principal():
    """Backend использует claims только из request-local ContextVar."""
    user = SimpleNamespace(pk="42")
    principal = Principal(user, {"scope": "write"}, "jwt")
    authorize = Mock(return_value=True)
    token = principal_context.set(principal)
    try:
        with patch(
            "jam.ext.django.backends.get_jam",
            return_value=SimpleNamespace(authorize=authorize),
        ):
            assert JamBackend().has_perm(user, "reports:read")
    finally:
        principal_context.reset(token)

    assert authorize.call_args.args[0] is principal


from django.test import RequestFactory, override_settings
from jam.ext.django._authentication import (
    detect_bearer_type,
    authenticate_request,
)
import base64
import json


def _segment(value):
    return (
        base64.urlsafe_b64encode(json.dumps(value).encode())
        .rstrip(b"=")
        .decode()
    )


def _request(*, authorization=None, session=None, method="get"):
    headers = {}
    if authorization is not None:
        headers["HTTP_AUTHORIZATION"] = authorization
    if session is not None:
        headers["HTTP_COOKIE"] = f"session={session}"
    request = getattr(RequestFactory(), method)("/", **headers)
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
