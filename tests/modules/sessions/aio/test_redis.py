# -*- coding: utf-8 -*-

from jam.exceptions import JamSessionNotFound
import pytest
from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis
from pytest_asyncio import fixture

from jam.aio.sessions.redis import RedisSessions


@fixture(scope="function")
async def fake_redis():
    return FakeAsyncRedis(decode_responses=True)


@fixture(scope="function")
async def redis_session_instance_no_crypt(fake_redis):
    return RedisSessions(
        redis_uri=fake_redis,
        redis_sessions_key="test",
        default_ttl=None,
        is_session_crypt=False,
    )


@fixture
async def aes_key():
    from jam.utils import generate_aes_key

    return generate_aes_key()


@fixture
async def f(aes_key):
    return Fernet(aes_key)


@fixture(scope="function")
async def redis_session_with_crypt(fake_redis, aes_key):
    return RedisSessions(
        redis_uri=fake_redis,
        redis_sessions_key="test",
        default_ttl=None,
        is_session_crypt=True,
        session_aes_secret=aes_key,
    )


@pytest.mark.asyncio
async def test_create_new_session(redis_session_instance_no_crypt, fake_redis):
    session = await redis_session_instance_no_crypt.create(
        session_key="test", data={"user_id": 1}
    )

    assert isinstance(session, str)
    assert len(session) > 0
    assert (session.split(":")[0]) == "test"

    stored_data = await fake_redis.hget(name="test:test", key=session)

    assert stored_data == '{"user_id": 1}'


@pytest.mark.asyncio
async def test_get_session(redis_session_instance_no_crypt):
    session = await redis_session_instance_no_crypt.create(
        session_key="test", data={"user_id": 1}
    )

    retrieved_data = await redis_session_instance_no_crypt.get(session)
    assert retrieved_data == {"user_id": 1}


@pytest.mark.asyncio
async def test_get_nonexistent_session(redis_session_instance_no_crypt):
    retrieved_data = await redis_session_instance_no_crypt.get(
        "nonexistent:session"
    )
    assert retrieved_data is None


@pytest.mark.asyncio
async def test_delete_session(redis_session_instance_no_crypt):
    session = await redis_session_instance_no_crypt.create(
        session_key="test", data={"user_id": 1}
    )
    await redis_session_instance_no_crypt.delete(session)
    retrieved_data = await redis_session_instance_no_crypt.get(session)
    assert retrieved_data is None


@pytest.mark.asyncio
async def test_session_ttl(redis_session_instance_no_crypt, fake_redis):
    redis_session_instance_no_crypt.ttl = 20  # Set TTL to 2 seconds
    session = await redis_session_instance_no_crypt.create(
        session_key="test", data={"user_id": 1}
    )
    ttl = await fake_redis.httl("test:test", session)
    assert ttl[0] <= 20 and ttl[0] > 0


@pytest.mark.asyncio
async def test_update_session(redis_session_instance_no_crypt):
    session = await redis_session_instance_no_crypt.create(
        session_key="test", data={"user_id": 1}
    )
    await redis_session_instance_no_crypt.update(session, {"user_id": 2})
    retrieved_data = await redis_session_instance_no_crypt.get(session)
    assert retrieved_data == {"user_id": 2}


@pytest.mark.asyncio
async def test_update_nonexistent_session(redis_session_instance_no_crypt):
    with pytest.raises(JamSessionNotFound):
        await redis_session_instance_no_crypt.update(
            "nonexistent:session", {"user_id": 2}
        )


@pytest.mark.asyncio
async def test_update_empty_session(redis_session_instance_no_crypt):
    session = await redis_session_instance_no_crypt.create("test", {})

    await redis_session_instance_no_crypt.update(session, {"updated": True})

    assert await redis_session_instance_no_crypt.get(session) == {
        "updated": True
    }


@pytest.mark.asyncio
async def test_rework_empty_session(redis_session_instance_no_crypt):
    old_session = await redis_session_instance_no_crypt.create("test", {})

    new_session = await redis_session_instance_no_crypt.rework(old_session)

    assert new_session != old_session
    assert await redis_session_instance_no_crypt.get(old_session) is None
    assert await redis_session_instance_no_crypt.get(new_session) == {}


@pytest.mark.asyncio
async def test_rework_nonexistent_session(redis_session_instance_no_crypt):
    with pytest.raises(JamSessionNotFound):
        await redis_session_instance_no_crypt.rework("nonexistent:session")


@pytest.mark.asyncio
async def test_create_session_empty_data(redis_session_instance_no_crypt):
    session = await redis_session_instance_no_crypt.create(
        session_key="test", data={}
    )
    assert isinstance(session, str)
    assert len(session) > 0
    assert (session.split(":")[0]) == "test"
    retrieved_data = await redis_session_instance_no_crypt.get(session)
    assert retrieved_data == {}


@pytest.mark.asyncio
async def test_create_new_session_crypt(
    redis_session_with_crypt, f, fake_redis
):
    session = await redis_session_with_crypt.create(
        session_key="test", data={"user_id": 1}
    )

    assert isinstance(session, str)
    assert len(session) > 0

    stored_data = await fake_redis.hget(name="test:test", key=session)

    assert stored_data != '{"user_id": 1}'

    assert stored_data.startswith("J$_")
    stored_data = stored_data.split("J$_")[1]
    decoded_data = f.decrypt(stored_data).decode()
    assert decoded_data == '{"user_id": 1}'


@pytest.mark.asyncio
async def test_get_crypt_session(redis_session_with_crypt, f, fake_redis):
    session = await redis_session_with_crypt.create(
        session_key="test", data={"user_id": 1}
    )

    assert session.startswith("J$_")

    retrieved_data = await redis_session_with_crypt.get(session)
    assert retrieved_data == {"user_id": 1}

    retrieved_data_from_redis = await fake_redis.hget("test:test", session)
    assert retrieved_data_from_redis != '{"user_id": 1}'
    decoded_retrieved_data_from_redis = f.decrypt(
        retrieved_data_from_redis.split("J$_")[1]
    ).decode()

    assert decoded_retrieved_data_from_redis == '{"user_id": 1}'


@pytest.mark.asyncio
@pytest.mark.parametrize("decode_responses", [True, False])
@pytest.mark.parametrize("is_session_crypt", [True, False])
async def test_get_normalizes_redis_response(
    decode_responses, is_session_crypt, aes_key
):
    fake_redis = FakeAsyncRedis(decode_responses=decode_responses)
    sessions = RedisSessions(
        redis_uri=fake_redis,
        redis_sessions_key="test",
        default_ttl=None,
        is_session_crypt=is_session_crypt,
        session_aes_secret=aes_key if is_session_crypt else None,
    )
    session = await sessions.create("test", {"user_id": 1})

    assert await sessions.get(session) == {"user_id": 1}
