# -*- coding: utf-8 -*-

import pytest
from unittest.mock import AsyncMock, MagicMock
from starlette.authentication import (
    UnauthenticatedUser,
)
from starlette.requests import HTTPConnection

pytestmark = pytest.mark.skip(
    "jam.ext is deferred until the module API rework is complete"
)

try:
    from jam.ext.starlette import (
        JWTBackend,
        SessionBackend,
        PASETOBackend,
        SimpleUser,
    )
except ImportError:
    pytest.skip(
        "jam.ext is deferred until the module API rework is complete",
        allow_module_level=True,
    )


@pytest.fixture
def jwt_config():
    return {"jwt": {"secret": "test-secret", "alg": "HS256"}}


@pytest.fixture
def session_config():
    return {"sessions": {"session_type": "json", "url": "redis://localhost"}}


@pytest.fixture
def paseto_config():
    return {
        "paseto": {
            "version": "v4",
            "purpose": "local",
            "secret_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        }
    }


@pytest.mark.asyncio
async def test_jwt_backend_from_cookie(jwt_config):
    backend = JWTBackend(config=jwt_config, cookie_name="access_token")

    mock_jwt = MagicMock()
    mock_jwt.decode.return_value = {"user_id": 1, "username": "bob"}
    backend._auth = mock_jwt

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"cookie", b"access_token=valid_token")]}
    )

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == ["authenticated"]
    assert user.payload["user_id"] == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_jwt_backend_from_header(jwt_config):
    backend = JWTBackend(config=jwt_config, header_name="Authorization")

    mock_jwt = MagicMock()
    mock_jwt.decode.return_value = {"user": "header_user"}
    backend._auth = mock_jwt

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"authorization", b"Bearer valid_token")]}
    )

    creds, user = await backend.authenticate(conn)  # type: ignore[union-attr]
    assert user.payload == {"user": "header_user"}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_jwt_backend_no_token_returns_unauthenticated(jwt_config):
    backend = JWTBackend(config=jwt_config, cookie_name="access_token")
    conn = HTTPConnection({"type": "http", "headers": []})

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result  # type: ignore[union-attr]
    assert creds.scopes == []  # type: ignore[union-attr]
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_jwt_backend_invalid_token_raises_error(jwt_config):
    backend = JWTBackend(config=jwt_config, header_name="Authorization")

    mock_jwt = MagicMock()
    mock_jwt.decode.side_effect = ValueError("Invalid token")
    backend._auth = mock_jwt

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"authorization", b"Bearer bad")]}
    )

    with pytest.raises(ValueError):
        await backend.authenticate(conn)


@pytest.mark.asyncio
async def test_session_backend_from_cookie(session_config):
    backend = SessionBackend(config=session_config, cookie_name="sessionId")

    mock_session = AsyncMock()
    mock_session.get.return_value = {"user_id": 42, "role": "admin"}
    backend._auth = mock_session

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"cookie", b"sessionId=sid123")]}
    )

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == ["authenticated"]
    assert user.payload["user_id"] == 42  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_session_backend_from_header(session_config):
    backend = SessionBackend(
        config=session_config, cookie_name=None, header_name="Authorization"
    )

    mock_session = AsyncMock()
    mock_session.get.return_value = {"user": "header_user"}
    backend._auth = mock_session

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"authorization", b"Bearer session123")]}
    )

    creds, user = await backend.authenticate(conn)  # type: ignore[union-attr]
    assert user.payload == {"user": "header_user"}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_session_backend_no_session_returns_unauthenticated(
    session_config,
):
    backend = SessionBackend(config=session_config, cookie_name="sessionId")

    mock_session = AsyncMock()
    mock_session.get.return_value = None
    backend._auth = mock_session

    conn = HTTPConnection({"type": "http", "headers": []})

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == []
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_session_backend_invalid_session_returns_unauthenticated(
    session_config,
):
    backend = SessionBackend(config=session_config, header_name="Authorization")

    mock_session = AsyncMock()
    mock_session.get.return_value = None
    backend._auth = mock_session

    conn = HTTPConnection(
        {
            "type": "http",
            "headers": [(b"authorization", b"Bearer broken")],
        }
    )

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == []
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_paseto_backend_from_cookie(paseto_config):
    backend = PASETOBackend(config=paseto_config, cookie_name="paseto")

    mock_paseto = MagicMock()
    mock_paseto.decode.return_value = {"user_id": 1, "username": "alice"}
    backend._auth = mock_paseto

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"cookie", b"paseto=valid_paseto")]}
    )

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == ["authenticated"]
    assert user.payload["user_id"] == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_paseto_backend_from_header(paseto_config):
    backend = PASETOBackend(config=paseto_config, header_name="Authorization")

    mock_paseto = MagicMock()
    mock_paseto.decode.return_value = {"user": "paseto_user"}
    backend._auth = mock_paseto

    conn = HTTPConnection(
        {
            "type": "http",
            "headers": [(b"authorization", b"Bearer valid_paseto")],
        }
    )

    creds, user = await backend.authenticate(conn)  # type: ignore[union-attr]
    assert user.payload == {"user": "paseto_user"}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_paseto_backend_no_token_returns_unauthenticated(paseto_config):
    backend = PASETOBackend(config=paseto_config, cookie_name="paseto")
    conn = HTTPConnection({"type": "http", "headers": []})

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == []
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_paseto_backend_invalid_token_returns_unauthenticated(
    paseto_config,
):
    backend = PASETOBackend(config=paseto_config, header_name="Authorization")

    mock_paseto = MagicMock()
    mock_paseto.decode.return_value = None
    backend._auth = mock_paseto

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"authorization", b"Bearer bad_paseto")]}
    )

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert creds.scopes == []
    assert isinstance(user, UnauthenticatedUser)


@pytest.mark.asyncio
async def test_custom_user_class(jwt_config):
    class CustomUser(SimpleUser):
        @property
        def name(self):
            return self.payload.get("username", "anonymous")

    backend = JWTBackend(
        config=jwt_config, cookie_name="access_token", user=CustomUser
    )

    mock_jwt = MagicMock()
    mock_jwt.decode.return_value = {"user_id": 1, "username": "custom_user"}
    backend._auth = mock_jwt

    conn = HTTPConnection(
        {"type": "http", "headers": [(b"cookie", b"access_token=valid_token")]}
    )

    result = await backend.authenticate(conn)

    assert result is not None
    creds, user = result
    assert isinstance(user, CustomUser)
    assert user.name == "custom_user"


def test_backend_requires_cookie_or_header():
    with pytest.raises(Exception):
        JWTBackend(config={"jwt": {"secret": "test", "alg": "HS256"}})


def test_jwt_backend_sets_state(jwt_config):
    backend = JWTBackend(config=jwt_config, cookie_name="access_token")
    conn = HTTPConnection({"type": "http", "headers": []})

    import asyncio

    asyncio.run(backend.authenticate(conn))

    assert hasattr(conn.state, "jwt")
