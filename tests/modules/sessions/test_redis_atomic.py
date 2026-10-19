"""Redis writes exercise actual Lua scripts against shared fake servers."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import inspect
from itertools import count

from cryptography.fernet import Fernet
from fakeredis import FakeAsyncRedis, FakeRedis, FakeServer
import pytest

from jam import Jam
from jam.aio import AsyncJam
from jam.aio.sessions.redis import RedisSessions as AsyncRedisSessions
from jam.exceptions import JamConfigurationError, JamError, JamSessionNotFound
from jam.sessions.redis import RedisSessions


async def call(method, *args, **kwargs):
    value = method(*args, **kwargs)
    return await value if inspect.isawaitable(value) else value


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@pytest.mark.parametrize(
    "options,expected",
    [
        ({}, 3600),
        ({"ttl": 60}, 60),
        ({"default_ttl": 40}, 40),
        ({"ttl": None}, None),
        ({"ttl": 0}, 0),
        ({"ttl": None, "default_ttl": 5}, None),
    ],
)
async def test_facade_ttl_contract(async_, options, expected):
    redis = FakeAsyncRedis() if async_ else FakeRedis()
    cfg = {"session": {"type": "redis", "redis_uri": redis, **options}}
    original = dict(cfg["session"])
    jam = (AsyncJam if async_ else Jam)(config=cfg)
    assert cfg["session"] == original
    assert jam.session.ttl == expected
    token = await call(jam.issue, {"id": "u"}, via="session")
    ttl = (await call(redis.httl, "sessions:auth", token))[0]
    assert ttl == -1 if not expected else 0 < ttl <= expected


@pytest.mark.parametrize("ttl", [-1, True, 1.5, "60"])
@pytest.mark.parametrize(
    "cls,client",
    [(RedisSessions, FakeRedis), (AsyncRedisSessions, FakeAsyncRedis)],
)
def test_invalid_ttl_before_writes(ttl, cls, client):
    with pytest.raises(JamConfigurationError) as error:
        cls(redis_uri=client(), ttl=ttl)
    assert error.value.error_code == "configuration.session.invalid_ttl"


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@pytest.mark.parametrize("encrypted", [False, True])
async def test_update_rotate_and_collisions(async_, encrypted):
    redis = FakeAsyncRedis() if async_ else FakeRedis()
    ids = (str(i) for i in count())
    cls = AsyncRedisSessions if async_ else RedisSessions
    storage = cls(
        redis_uri=redis,
        ttl=60,
        id_factory=lambda: next(ids),
        is_session_crypt=encrypted,
        session_aes_secret=Fernet.generate_key(),
    )
    token = await call(storage.create, "auth", {})
    await call(storage.update, token, {"n": 2})
    assert (await call(redis.httl, "sessions:auth", token))[0] > 0
    rotated = await call(storage.rework, token)
    assert await call(storage.get, token) is None
    assert await call(storage.get, rotated) == {"n": 2}
    assert (await call(redis.httl, "sessions:auth", rotated))[0] > 0
    with pytest.raises(JamSessionNotFound):
        await call(storage.update, token, {"n": 3})
    await call(redis.hexpire, "sessions:auth", 0, rotated)
    with pytest.raises(JamSessionNotFound):
        await call(storage.update, rotated, {})
    with pytest.raises(JamSessionNotFound):
        await call(storage.rework, rotated)


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
async def test_id_collision_never_overwrites(async_):
    redis = FakeAsyncRedis() if async_ else FakeRedis()
    cls = AsyncRedisSessions if async_ else RedisSessions
    storage = cls(redis_uri=redis, id_factory=lambda: "fixed")
    token = await call(storage.create, "auth", {"original": True})
    for operation, args in (
        (storage.create, ("auth", {})),
        (storage.rework, (token,)),
    ):
        with pytest.raises(JamError) as error:
            await call(operation, *args)
        assert error.value.error_code == "sessions.id_collision"
    assert await call(storage.get, token) == {"original": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@pytest.mark.parametrize("operation", ["update", "rework"])
@pytest.mark.parametrize("revoke", ["delete", "clear"])
async def test_revoke_immediately_before_write(
    async_, operation, revoke, monkeypatch
):
    redis = FakeAsyncRedis() if async_ else FakeRedis()
    storage = (AsyncRedisSessions if async_ else RedisSessions)(redis_uri=redis)
    token = await call(storage.create, "auth", {})
    original = redis.eval

    def evaluate(*args):
        getattr(storage, revoke)(token if revoke == "delete" else "auth")
        return original(*args)

    async def aevaluate(*args):
        await getattr(storage, revoke)(token if revoke == "delete" else "auth")
        return await original(*args)

    monkeypatch.setattr(redis, "eval", aevaluate if async_ else evaluate)
    with pytest.raises(JamSessionNotFound):
        await call(
            getattr(storage, operation),
            token,
            *([{}] if operation == "update" else []),
        )
    assert await call(redis.hlen, "sessions:auth") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
async def test_only_one_concurrent_rotation_succeeds(async_):
    server = FakeServer()
    cls, client = (
        (AsyncRedisSessions, FakeAsyncRedis)
        if async_
        else (RedisSessions, FakeRedis)
    )
    a, b = [cls(redis_uri=client(server=server)) for _ in range(2)]
    token = await call(a.create, "auth", {"n": 1})
    if async_:
        results = await asyncio.gather(
            a.rework(token), b.rework(token), return_exceptions=True
        )
    else:
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(s.rework, token) for s in (a, b)]
            results = []
            for future in futures:
                try:
                    results.append(future.result())
                except JamSessionNotFound as error:
                    results.append(error)
    assert sum(isinstance(r, str) for r in results) == 1
    assert sum(isinstance(r, JamSessionNotFound) for r in results) == 1
    assert await call(a._redis.hlen, "sessions:auth") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@pytest.mark.parametrize("operation", ["create", "update", "rework"])
async def test_expiry_error_cleans_new_field(async_, operation, monkeypatch):
    redis = FakeAsyncRedis() if async_ else FakeRedis()
    storage = (AsyncRedisSessions if async_ else RedisSessions)(redis_uri=redis)
    token = await call(storage.create, "auth", {"old": True})
    original = redis.eval

    def fail_expiry(script, *args):
        return original(script.replace("'HEXPIRE'", "'NO_SUCH_COMMAND'"), *args)

    async def afail_expiry(script, *args):
        return await original(
            script.replace("'HEXPIRE'", "'NO_SUCH_COMMAND'"), *args
        )

    monkeypatch.setattr(redis, "eval", afail_expiry if async_ else fail_expiry)
    args = (
        ("auth", {})
        if operation == "create"
        else (token, {})
        if operation == "update"
        else (token,)
    )
    with pytest.raises(JamError) as error:
        await call(getattr(storage, operation), *args)
    assert error.value.error_code == "sessions.storage_error"
    assert error.value.__cause__ is not None
    assert await call(redis.hlen, "sessions:auth") == (
        0 if operation == "update" else 1
    )
