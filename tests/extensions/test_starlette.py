# -*- coding: utf-8 -*-

from unittest.mock import MagicMock

import pytest
from starlette.authentication import AuthenticationError
from starlette.requests import HTTPConnection

from jam.authz import Principal
from jam.exceptions import JamValidationError
from jam.ext import CredentialSource
from jam.ext.starlette import JamAuthBackend, JamUser


def connection(headers: list[tuple[bytes, bytes]]) -> HTTPConnection:
    return HTTPConnection(
        {
            "type": "http",
            "headers": headers,
            "query_string": b"",
        }
    )


@pytest.mark.asyncio
async def test_backend_authenticates_any_jam_credential():
    jam = MagicMock()
    principal = Principal(
        {"id": "42", "username": "bob"},
        {"permissions": ["post:read"]},
        "jwt",
    )
    jam.authenticate.return_value = principal
    backend = JamAuthBackend(jam)

    credentials, user = await backend.authenticate(
        connection([(b"authorization", b"Bearer valid")])
    )

    jam.authenticate.assert_called_once_with("valid", via=None)
    assert credentials.scopes == ["authenticated", "post:read"]
    assert isinstance(user, JamUser)
    assert user.principal is principal
    assert user.display_name == "bob"


@pytest.mark.asyncio
async def test_backend_supports_cookie_and_explicit_via():
    jam = MagicMock()
    jam.authenticate.return_value = Principal({"id": "42"}, {}, "session")
    backend = JamAuthBackend(
        jam,
        sources=[CredentialSource.cookie("session")],
        via="session",
    )
    conn = connection([(b"cookie", b"session=session-id")])

    await backend.authenticate(conn)

    jam.authenticate.assert_called_once_with("session-id", via="session")
    assert conn.state.principal.subject["id"] == "42"


@pytest.mark.asyncio
async def test_backend_returns_none_without_credential():
    jam = MagicMock()
    backend = JamAuthBackend(jam)

    assert await backend.authenticate(connection([])) is None
    jam.authenticate.assert_not_called()


@pytest.mark.asyncio
async def test_backend_rejects_invalid_credential_by_default():
    jam = MagicMock()
    jam.authenticate.side_effect = JamValidationError(
        message="secret decoder detail"
    )
    backend = JamAuthBackend(jam)

    with pytest.raises(AuthenticationError, match="Invalid authentication"):
        await backend.authenticate(
            connection([(b"authorization", b"Bearer invalid")])
        )


@pytest.mark.asyncio
async def test_backend_can_treat_invalid_credential_as_anonymous():
    jam = MagicMock()
    jam.authenticate.side_effect = JamValidationError(message="invalid")
    backend = JamAuthBackend(jam, reject_invalid=False)

    result = await backend.authenticate(
        connection([(b"authorization", b"Bearer invalid")])
    )

    assert result is None
