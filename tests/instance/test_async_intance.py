# -*- coding: utf-8 -*-

import pytest
from fakeredis import FakeAsyncRedis
from pytest_asyncio import fixture

from jam.aio import Jam


pytestmark = pytest.mark.skip(
    reason="jam.aio is deferred until the sync API rework is complete"
)


@fixture
async def jam_jwt_instance():
    jam = Jam(config={"jwt": {"alg": "HS256", "secret_key": "SECRET"}})
    return jam


@fixture
async def jam_session_instance():
    jam = Jam(
        config={
            "session": {
                "sessions_type": "redis",
                "redis_uri": FakeAsyncRedis(decode_responses=True),
            }
        }
    )
    return jam


@pytest.mark.asyncio
async def test_jwt_instance(jam_jwt_instance):
    jwt_payload = await jam_jwt_instance.jwt_make_payload(
        exp=89898989, data={"sub": "user123"}
    )
    assert jwt_payload["sub"] == "user123"

    token = await jam_jwt_instance.jwt_create(jwt_payload)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # JWT has three parts separated by dots
    decoded_payload = await jam_jwt_instance.jwt_decode(
        token, check_exp=False, check_list=False
    )
    assert decoded_payload == jwt_payload


@pytest.mark.asyncio
async def test_session_instance(jam_session_instance):
    session_data = {"user_id": "user123"}
    session_id = await jam_session_instance.session_create(
        session_key="user", data=session_data
    )
    assert isinstance(session_id, str)
    assert len(session_id) > 0

    retrieved_data = await jam_session_instance.session_get(session_id)
    assert retrieved_data == session_data

    await jam_session_instance.session_delete(session_id)
    assert await jam_session_instance.session_get(session_id) is None
