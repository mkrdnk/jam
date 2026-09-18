from types import SimpleNamespace
from unittest.mock import patch

import pytest


pytest.importorskip("rest_framework")


from rest_framework.exceptions import AuthenticationFailed

from jam.authz import Principal
from jam.ext.django._authentication import InvalidCredential
from jam.ext.django.drf import JamAuthentication


def test_drf_uses_shared_bearer_authentication_flow():
    """DRF использует общий путь Bearer-аутентификации."""
    user = SimpleNamespace(pk="42")
    principal = Principal(user, {"scope": "read"}, "jwt")
    raw_request = SimpleNamespace()
    request = SimpleNamespace(_request=raw_request)

    with patch(
        "jam.ext.django.drf.authentication.authenticate_request",
        return_value=principal,
    ) as authenticate:
        assert JamAuthentication().authenticate(request) == (user, principal)

    authenticate.assert_called_once_with(raw_request, session_source=None)


def test_drf_maps_shared_invalid_credential_to_authentication_failure():
    """DRF преобразует InvalidCredential в стандартный отказ аутентификации."""
    request = SimpleNamespace(_request=SimpleNamespace())

    with patch(
        "jam.ext.django.drf.authentication.authenticate_request",
        side_effect=InvalidCredential,
    ):
        with pytest.raises(AuthenticationFailed):
            JamAuthentication().authenticate(request)
