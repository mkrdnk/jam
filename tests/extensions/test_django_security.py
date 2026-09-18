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
