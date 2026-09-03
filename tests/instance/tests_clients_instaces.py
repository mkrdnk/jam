# -*- coding: utf-8 -*-

import pytest
from pytest_asyncio import fixture

from jam.exceptions import JamJWSVerificationError
from jam.tests import TestAsyncJam, TestJam
from jam.tests.fakers import invalid_token


@pytest.fixture
def client_instance() -> TestJam:
    return TestJam()


@fixture
async def async_client_instance() -> TestAsyncJam:
    return TestAsyncJam()


def test_client_instance(client_instance):
    valid_token = client_instance.issue(
        {"id": "user-1", "user": 1},
        via="jwt",
    )

    principal = client_instance.authenticate(valid_token)
    assert principal.claims["user"] == 1
    assert principal.subject["id"] == "user-1"

    invalid_token_ = invalid_token()

    with pytest.raises(JamJWSVerificationError):
        client_instance.authenticate(invalid_token_, via="jwt")

    session_id = client_instance.issue(
        {"id": "user-1", "user": 1},
        via="session",
    )

    session_principal = client_instance.authenticate(session_id)
    assert session_principal.claims["user"] == 1

    otp_code = client_instance.otp.now()

    assert client_instance.otp.verify(otp_code) is True
    assert client_instance.otp.verify("invalid") is False


def test_client_authorization_can_be_configured():
    client = TestJam(authorization=False)

    assert client.authorize({"id": "user-1"}, "post:delete") is False
    assert client.policy.calls == [
        ({"id": "user-1"}, "post:delete", None),
    ]


def test_client_instances_do_not_share_sessions():
    first = TestJam()
    second = TestJam()

    session_id = first.issue({"id": "user-1"}, via="session")

    assert first.session.get(session_id) is not None
    assert second.session.get(session_id) is None


def test_client_exposes_current_module_api():
    client = TestJam(oauth2_providers=["github"])

    paseto = client.issue({"id": "user-1"}, via="paseto")
    encrypted = client.jwt.encrypt({"id": "user-1"})

    assert client.authenticate(paseto).subject["id"] == "user-1"
    assert client.authenticate(encrypted).subject["id"] == "user-1"
    assert client.oauth2["github"].fetch_token("code") == {
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "token_type": "bearer",
    }


@pytest.mark.asyncio
async def test_async_client_instance(async_client_instance):
    valid_token = await async_client_instance.issue(
        {"id": "user-1", "user": 1},
        via="jwt",
    )

    principal = await async_client_instance.authenticate(valid_token)
    assert principal.claims["user"] == 1

    invalid_token_ = invalid_token()

    with pytest.raises(JamJWSVerificationError):
        await async_client_instance.authenticate(invalid_token_, via="jwt")

    session_id = await async_client_instance.issue(
        {"id": "user-1", "user": 1},
        via="session",
    )

    session_principal = await async_client_instance.authenticate(session_id)
    assert session_principal.claims["user"] == 1

    oauth_client = TestAsyncJam(oauth2_providers=["github"])
    oauth_token = await oauth_client.oauth2["github"].fetch_token("code")
    assert oauth_token["access_token"] == "test-access-token"
