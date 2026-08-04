# -*- coding: utf-8 -*-

import pytest
from pytest_asyncio import fixture

from jam.tests import TestAsyncJam, TestJam
from jam.tests.fakers import invalid_token


@pytest.fixture
def client_instance() -> TestJam:
    return TestJam()


@fixture
async def async_client_instance() -> TestAsyncJam:
    return TestAsyncJam()


def test_client_instance(client_instance):
    payload = {"user": 1}
    valid_token = client_instance.jwt_encode(payload=payload)

    verify = client_instance.jwt_decode(
        valid_token, check_exp=False, check_list=False
    )
    assert verify["user"] == 1

    invalid_token_ = invalid_token()

    with pytest.raises(ValueError):
        client_instance.jwt_decode(invalid_token_, check_exp=False, check_list=False)

    session_id = client_instance.session_create(
        session_key="TEST", data={"user": 1}
    )

    session_data = client_instance.session_get(session_id)
    assert session_data == {"user": 1}

    otp_code = client_instance.otp_code(
        secret="fdfdfd",
    )

    assert (
        client_instance.otp_verify_code(
            secret="fdfd", code=otp_code, factor=None, look_ahead=1
        )
        is True
    )

    assert (
        client_instance.otp_verify_code(
            secret="fdfd", code="dfdfd", factor=None, look_ahead=1
        )
        is False
    )


@pytest.mark.skip(
    reason="jam.aio is deferred until the sync API rework is complete"
)
@pytest.mark.asyncio
async def test_async_client_instance(async_client_instance):
    payload = {"user": 1}
    valid_token = await async_client_instance.jwt_encode(payload=payload)

    verify = await async_client_instance.jwt_decode(
        valid_token, check_exp=False, check_list=False
    )
    assert verify["user"] == 1

    invalid_token_ = invalid_token()

    with pytest.raises(ValueError):
        await async_client_instance.jwt_decode(
            invalid_token_, check_exp=False, check_list=False
        )

    session_id = await async_client_instance.session_create(
        session_key="TEST", data={"user": 1}
    )

    session_data = await async_client_instance.session_get(session_id)
    assert session_data == {"user": 1}

    otp_code = await async_client_instance.otp_code(
        secret="fdfdfd",
    )

    assert (
        await async_client_instance.otp_verify_code(
            secret="fdfd", code=otp_code, factor=None, look_ahead=1
        )
        is True
    )

    assert (
        await async_client_instance.otp_verify_code(
            secret="fdfd", code="dfdfd", factor=None, look_ahead=1
        )
        is False
    )
