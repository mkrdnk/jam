# -*- coding: utf-8 -*-

from unittest.mock import MagicMock

import pytest

from jam.authz import Principal
from jam.exceptions import JamConfigurationError, JamValidationError
from jam.ext import CredentialSource
from jam.ext._base import Authenticator


def test_sources_are_checked_in_order_and_parse_scheme_case_insensitively():
    authenticator = Authenticator(
        MagicMock(),
        sources=[
            CredentialSource.bearer(),
            CredentialSource.cookie("session"),
        ],
    )

    assert authenticator.extract(
        headers={"Authorization": "bearer token"},
        cookies={"session": "session-id"},
    ) == ("token", CredentialSource.bearer())
    assert authenticator.extract(
        headers={},
        cookies={"session": "session-id"},
    ) == ("session-id", CredentialSource.cookie("session"))


def test_authentication_result_preserves_expected_error():
    jam = MagicMock()
    jam.authenticate.side_effect = JamValidationError(message="invalid")
    result = Authenticator(jam).authenticate("token")

    assert not result.is_authenticated
    assert isinstance(result.error, JamValidationError)
    assert result.token == "token"


def test_configuration_errors_are_not_hidden():
    jam = MagicMock()
    jam.authenticate.side_effect = JamConfigurationError(message="broken")

    with pytest.raises(JamConfigurationError):
        Authenticator(jam).authenticate("token")


def test_unexpected_errors_are_not_hidden():
    jam = MagicMock()
    jam.authenticate.side_effect = RuntimeError("bug")

    with pytest.raises(RuntimeError, match="bug"):
        Authenticator(jam).authenticate("token")


def test_successful_authentication_returns_principal():
    jam = MagicMock()
    principal = Principal({"id": "42"}, {}, "jwt")
    jam.authenticate.return_value = principal

    result = Authenticator(jam).authenticate("token")

    assert result.is_authenticated
    assert result.principal is principal
