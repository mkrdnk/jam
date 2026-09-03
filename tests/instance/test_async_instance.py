# -*- coding: utf-8 -*-

import pytest
from fakeredis import FakeAsyncRedis

from jam.aio import AsyncJam, Jam
from jam.authz import Principal


def test_legacy_name_is_alias():
    assert Jam is AsyncJam


@pytest.mark.asyncio
async def test_jwt_issue_and_authenticate():
    jam = AsyncJam(
        config={
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "SECRET",
                }
            }
        }
    )

    token = await jam.issue({"id": "user123"})
    principal = await jam.authenticate(token)

    assert isinstance(token, str)
    assert isinstance(principal, Principal)
    assert principal.subject["id"] == "user123"
    assert principal.token_type == "jwt"


@pytest.mark.asyncio
async def test_jwt_async_allowlist():
    jam = AsyncJam(
        config={
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "SECRET",
                    "list": {
                        "backend": "memory",
                        "type": "white",
                    },
                }
            }
        }
    )

    token = await jam.issue({"id": "user123"})

    assert await jam._jwt_list.check(token)
    assert (await jam.authenticate(token)).subject["id"] == "user123"


@pytest.mark.asyncio
async def test_async_redis_session():
    redis = FakeAsyncRedis(decode_responses=True)
    jam = AsyncJam(
        config={
            "session": {
                "type": "redis",
                "redis_uri": redis,
            }
        }
    )

    session_id = await jam.issue({"id": "user123"}, via="session")
    principal = await jam.authenticate(session_id)

    assert principal.subject["id"] == "user123"
    assert principal.token_type == "session"

    await jam.session.delete(session_id)
    assert await jam.session.get(session_id) is None
