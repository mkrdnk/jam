# -*- coding: utf-8 -*-

import asyncio
import hashlib
import json
from threading import Event
from unittest.mock import AsyncMock, Mock

from fakeredis import FakeAsyncRedis, FakeRedis
import pytest

from jam import Jam
from jam.aio import AsyncJam
from jam.aio.lists import build_list as build_async_list
from jam.aio.lists.json import AsyncJSONList
import jam.aio.lists.redis as async_redis_module
from jam.aio.lists.redis import RedisList as AsyncRedisList
from jam.exceptions import JamConfigurationError, JamValidationError
from jam.lists import build_list
from jam.lists._fingerprint import token_fingerprint
from jam.lists.json import JSONList
import jam.lists.redis as redis_module
from jam.lists.redis import RedisList


TOKEN = "Bearer секрет-" + ("x" * 2048)


def test_token_fingerprint_is_stable_sha256():
    assert token_fingerprint("токен") == hashlib.sha256(
        "токен".encode()
    ).hexdigest()


@pytest.mark.parametrize("token", ["", "\ud800", None, 1, b"token"])
def test_token_fingerprint_rejects_malformed_input(token):
    with pytest.raises(JamValidationError):
        token_fingerprint(token)


@pytest.mark.parametrize("ttl", [0, -1, True, False, 1.5, "60"])
def test_sync_redis_rejects_invalid_ttl(ttl):
    with pytest.raises(JamConfigurationError):
        RedisList(
            type="black",
            redis=FakeRedis(decode_responses=True),
            ttl=ttl,
        )


@pytest.mark.parametrize("ttl", [0, -1, True, False, 1.5, "60"])
def test_async_redis_rejects_invalid_ttl(ttl):
    with pytest.raises(JamConfigurationError):
        AsyncRedisList(
            type="black",
            redis=FakeAsyncRedis(decode_responses=True),
            ttl=ttl,
        )


@pytest.mark.parametrize("backend", ["redis", "json"])
@pytest.mark.parametrize("legacy_raw_keys", [None, 0, 1, "false"])
def test_sync_factory_rejects_invalid_legacy_mode(
    backend, legacy_raw_keys, tmp_path
):
    config = {
        "backend": backend,
        "type": "black",
        "legacy_raw_keys": legacy_raw_keys,
    }
    if backend == "redis":
        config["redis"] = FakeRedis(decode_responses=True)
    else:
        config["json_path"] = str(tmp_path / "tokens.json")

    with pytest.raises(JamConfigurationError):
        build_list(config)


@pytest.mark.parametrize("backend", ["redis", "json"])
@pytest.mark.parametrize("legacy_raw_keys", [None, 0, 1, "false"])
def test_async_factory_rejects_invalid_legacy_mode(
    backend, legacy_raw_keys, tmp_path
):
    config = {
        "backend": backend,
        "type": "black",
        "legacy_raw_keys": legacy_raw_keys,
    }
    if backend == "redis":
        config["redis"] = FakeAsyncRedis(decode_responses=True)
    else:
        config["json_path"] = str(tmp_path / "tokens.json")

    with pytest.raises(JamConfigurationError):
        build_async_list(config)


def test_sync_factory_preserves_config_and_passes_redis_client():
    client = FakeRedis(decode_responses=True)
    config = {
        "backend": "redis",
        "type": "black",
        "redis": client,
        "ttl": 60,
        "legacy_raw_keys": False,
    }
    original = config.copy()

    token_list = build_list(config)

    assert config == original
    token_list.add(TOKEN)
    assert token_list.check(TOKEN)
    token_list.close()


@pytest.mark.asyncio
async def test_async_factory_preserves_config_and_passes_redis_client():
    client = FakeAsyncRedis(decode_responses=True)
    config = {
        "backend": "redis",
        "type": "black",
        "redis": client,
        "ttl": 60,
        "legacy_raw_keys": False,
    }
    original = config.copy()

    token_list = build_async_list(config)

    assert config == original
    await token_list.add(TOKEN)
    assert await token_list.check(TOKEN)
    await token_list.aclose()


def test_sync_facade_passes_strict_compatibility_setting():
    client = FakeRedis(decode_responses=True)
    client.set(f"revoked:{TOKEN}", "1")
    config = {
        "lists": {
            "revoked": {
                "backend": "redis",
                "redis": client,
                "legacy_raw_keys": False,
            }
        }
    }
    original = {
        "lists": {
            "revoked": {
                "backend": "redis",
                "redis": client,
                "legacy_raw_keys": False,
            }
        }
    }

    jam = Jam(config=config)

    assert config == original
    assert not jam.lists["revoked"].check(TOKEN)


@pytest.mark.asyncio
async def test_async_facade_passes_strict_compatibility_setting():
    client = FakeAsyncRedis(decode_responses=True)
    await client.set(f"revoked:{TOKEN}", "1")
    config = {
        "lists": {
            "revoked": {
                "backend": "redis",
                "redis": client,
                "legacy_raw_keys": False,
            }
        }
    }
    original = {
        "lists": {
            "revoked": {
                "backend": "redis",
                "redis": client,
                "legacy_raw_keys": False,
            }
        }
    }

    jam = AsyncJam(config=config)

    assert config == original
    assert not await jam.lists["revoked"].check(TOKEN)


def test_sync_redis_writes_only_v2_fingerprint_and_preserves_ttl():
    client = FakeRedis(decode_responses=True)
    token_list = RedisList(
        type="black",
        prefix="revoked",
        redis=client,
        ttl=60,
    )

    token_list.add(TOKEN)

    keys = client.keys("*")
    assert keys == [f"revoked:v2:{token_fingerprint(TOKEN)}"]
    assert all(TOKEN not in key for key in keys)
    assert TOKEN not in " ".join(str(value) for value in client.mget(keys))
    assert client.ttl(keys[0]) in {59, 60}


@pytest.mark.asyncio
async def test_async_redis_writes_only_v2_fingerprint_and_preserves_ttl():
    client = FakeAsyncRedis(decode_responses=True)
    token_list = AsyncRedisList(
        type="black",
        prefix="revoked",
        redis=client,
        ttl=60,
    )

    await token_list.add(TOKEN)

    keys = await client.keys("*")
    assert keys == [f"revoked:v2:{token_fingerprint(TOKEN)}"]
    assert all(TOKEN not in key for key in keys)
    values = await client.mget(keys)
    assert TOKEN not in " ".join(str(value) for value in values)
    assert await client.ttl(keys[0]) in {59, 60}


def test_sync_redis_dual_reads_and_deletes_legacy_entry():
    client = FakeRedis(decode_responses=True)
    client.set(f"revoked:{TOKEN}", "1")
    token_list = RedisList(
        type="black",
        prefix="revoked",
        redis=client,
    )

    assert token_list.check(TOKEN)

    token_list.add(TOKEN)
    token_list.delete(TOKEN)

    assert not client.exists(f"revoked:{TOKEN}")
    assert not client.exists(f"revoked:v2:{token_fingerprint(TOKEN)}")


@pytest.mark.asyncio
async def test_async_redis_dual_reads_and_deletes_legacy_entry():
    client = FakeAsyncRedis(decode_responses=True)
    await client.set(f"revoked:{TOKEN}", "1")
    token_list = AsyncRedisList(
        type="black",
        prefix="revoked",
        redis=client,
    )

    assert await token_list.check(TOKEN)

    await token_list.add(TOKEN)
    await token_list.delete(TOKEN)

    assert not await client.exists(f"revoked:{TOKEN}")
    assert not await client.exists(
        f"revoked:v2:{token_fingerprint(TOKEN)}"
    )


def test_sync_redis_strict_mode_never_uses_raw_legacy_key():
    client = FakeRedis(decode_responses=True)
    client.set(f"revoked:{TOKEN}", "1")
    client.exists = Mock(wraps=client.exists)
    client.mget = Mock(wraps=client.mget)
    client.delete = Mock(wraps=client.delete)
    token_list = RedisList(
        type="black",
        prefix="revoked",
        redis=client,
        legacy_raw_keys=False,
    )

    assert not token_list.check(TOKEN)
    assert token_list.check_many([TOKEN]) == {TOKEN: False}
    token_list.delete_many([TOKEN])

    calls = (
        client.exists.call_args_list
        + client.mget.call_args_list
        + client.delete.call_args_list
    )
    assert TOKEN not in repr(calls)
    assert client.exists(f"revoked:{TOKEN}")


@pytest.mark.asyncio
async def test_async_redis_strict_mode_never_uses_raw_legacy_key():
    client = FakeAsyncRedis(decode_responses=True)
    await client.set(f"revoked:{TOKEN}", "1")
    client.exists = Mock(wraps=client.exists)
    client.mget = Mock(wraps=client.mget)
    client.delete = Mock(wraps=client.delete)
    token_list = AsyncRedisList(
        type="black",
        prefix="revoked",
        redis=client,
        legacy_raw_keys=False,
    )

    assert not await token_list.check(TOKEN)
    assert await token_list.check_many([TOKEN]) == {TOKEN: False}
    await token_list.delete_many([TOKEN])

    calls = (
        client.exists.call_args_list
        + client.mget.call_args_list
        + client.delete.call_args_list
    )
    assert TOKEN not in repr(calls)
    assert await client.exists(f"revoked:{TOKEN}")


def test_sync_redis_batches_backend_operations():
    client = FakeRedis(decode_responses=True)
    client.pipeline = Mock(wraps=client.pipeline)
    token_list = RedisList(type="black", redis=client)

    token_list.add_many(["one", "two", "two"])

    assert client.pipeline.call_count == 1
    client.mget = Mock(wraps=client.mget)
    assert token_list.check_many(["one", "missing"]) == {
        "one": True,
        "missing": False,
    }
    assert client.mget.call_count == 2

    client.delete = Mock(wraps=client.delete)
    token_list.delete_many(["one", "two"])
    assert client.delete.call_count == 1


@pytest.mark.asyncio
async def test_async_redis_batches_backend_operations():
    client = FakeAsyncRedis(decode_responses=True)
    client.pipeline = Mock(wraps=client.pipeline)
    token_list = AsyncRedisList(type="black", redis=client)

    await token_list.add_many(["one", "two", "two"])

    assert client.pipeline.call_count == 1
    client.mget = Mock(wraps=client.mget)
    assert await token_list.check_many(["one", "missing"]) == {
        "one": True,
        "missing": False,
    }
    assert client.mget.call_count == 2

    client.delete = Mock(wraps=client.delete)
    await token_list.delete_many(["one", "two"])
    assert client.delete.call_count == 1


def test_sync_redis_closes_only_owned_client(monkeypatch):
    external = FakeRedis(decode_responses=True)
    external.close = Mock()
    RedisList(type="black", redis=external).close()
    external.close.assert_not_called()

    owned = FakeRedis(decode_responses=True)
    owned.close = Mock()
    from_url = Mock(return_value=owned)
    monkeypatch.setattr(redis_module.Redis, "from_url", from_url)
    token_list = RedisList(type="black", redis_uri="redis://owned")

    token_list.close()
    token_list.close()

    owned.close.assert_called_once_with()


def test_sync_redis_retries_failed_owned_client_close(monkeypatch):
    owned = FakeRedis(decode_responses=True)
    owned.close = Mock(side_effect=[RuntimeError("close failed"), None])
    monkeypatch.setattr(
        redis_module.Redis,
        "from_url",
        Mock(return_value=owned),
    )
    token_list = RedisList(type="black", redis_uri="redis://owned")

    with pytest.raises(RuntimeError, match="close failed"):
        token_list.close()
    token_list.close()

    assert owned.close.call_count == 2


@pytest.mark.asyncio
async def test_async_redis_closes_only_owned_client(monkeypatch):
    external = FakeAsyncRedis(decode_responses=True)
    external.aclose = AsyncMock()
    await AsyncRedisList(type="black", redis=external).aclose()
    external.aclose.assert_not_awaited()

    owned = FakeAsyncRedis(decode_responses=True)
    owned.aclose = AsyncMock()
    from_url = Mock(return_value=owned)
    monkeypatch.setattr(async_redis_module.Redis, "from_url", from_url)
    token_list = AsyncRedisList(type="black", redis_uri="redis://owned")

    await token_list.aclose()
    await token_list.aclose()

    owned.aclose.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_async_redis_retries_failed_owned_client_close(monkeypatch):
    owned = FakeAsyncRedis(decode_responses=True)
    owned.aclose = AsyncMock(
        side_effect=[RuntimeError("close failed"), None]
    )
    monkeypatch.setattr(
        async_redis_module.Redis,
        "from_url",
        Mock(return_value=owned),
    )
    token_list = AsyncRedisList(type="black", redis_uri="redis://owned")

    with pytest.raises(RuntimeError, match="close failed"):
        await token_list.aclose()
    await token_list.aclose()

    assert owned.aclose.await_count == 2


def test_json_writes_only_unique_v2_documents(tmp_path):
    path = tmp_path / "tokens.json"
    token_list = JSONList(type="black", json_path=str(path))

    token_list.add(TOKEN)
    token_list.add(TOKEN)
    token_list.add_many([TOKEN, "два", "два"])

    documents = token_list._db.all()
    assert documents == [
        {"version": 2, "fingerprint": token_fingerprint(TOKEN)},
        {"version": 2, "fingerprint": token_fingerprint("два")},
    ]
    token_list.close()
    assert TOKEN not in path.read_text()


def test_json_close_is_idempotent(tmp_path):
    token_list = JSONList(
        type="black",
        json_path=str(tmp_path / "tokens.json"),
    )
    token_list._db.close = Mock(wraps=token_list._db.close)

    token_list.close()
    token_list.close()

    token_list._db.close.assert_called_once_with()


def test_json_dual_reads_and_deletes_legacy_documents(tmp_path):
    token_list = JSONList(
        type="black",
        json_path=str(tmp_path / "tokens.json"),
    )
    token_list._db.insert({"token": TOKEN})

    assert token_list.check(TOKEN)

    token_list.add(TOKEN)
    token_list.delete(TOKEN)

    assert token_list._db.all() == []


def test_json_strict_mode_ignores_legacy_documents(tmp_path):
    token_list = JSONList(
        type="black",
        json_path=str(tmp_path / "tokens.json"),
        legacy_raw_keys=False,
    )
    token_list._db.insert({"token": TOKEN})

    assert not token_list.check(TOKEN)
    assert token_list.check_many([TOKEN]) == {TOKEN: False}
    token_list.delete_many([TOKEN])

    assert token_list._db.all() == [{"token": TOKEN}]


def test_json_batches_reads_inserts_and_deletes(tmp_path):
    token_list = JSONList(
        type="black",
        json_path=str(tmp_path / "tokens.json"),
    )
    token_list._db.insert_multiple = Mock(
        wraps=token_list._db.insert_multiple
    )
    token_list.add_many(["one", "two", "two"])
    assert token_list._db.insert_multiple.call_count == 1

    token_list._db.all = Mock(wraps=token_list._db.all)
    token_list._db.search = Mock(
        side_effect=AssertionError("check_many must not search per token")
    )
    assert token_list.check_many(["one", "missing"]) == {
        "one": True,
        "missing": False,
    }
    assert token_list._db.all.call_count == 1

    token_list._db.remove = Mock(wraps=token_list._db.remove)
    token_list.delete_many(["one", "two"])
    assert token_list._db.remove.call_count == 1


@pytest.mark.asyncio
async def test_async_json_compatibility_and_lifecycle(tmp_path):
    path = tmp_path / "tokens.json"
    token_list = AsyncJSONList(type="black", json_path=str(path))
    token_list._list._db.insert({"token": TOKEN})

    async with token_list as entered:
        assert entered is token_list
        assert await token_list.check(TOKEN)
        await token_list.add_many(["one", "one", "два"])
        assert await token_list.check_many(["one", "два", "missing"]) == {
            "one": True,
            "два": True,
            "missing": False,
        }
        await token_list.delete_many([TOKEN, "one", "два"])

    await token_list.aclose()
    parsed = json.loads(path.read_text())
    assert all(TOKEN not in repr(table) for table in parsed.values())


@pytest.mark.asyncio
async def test_async_json_serializes_workers_after_cancellation(tmp_path):
    token_list = AsyncJSONList(
        type="black",
        json_path=str(tmp_path / "tokens.json"),
    )
    first_db_call_started = Event()
    release_first_db_call = Event()
    second_worker_started = Event()
    second_db_call_started = Event()
    original_insert_multiple = token_list._list._db.insert_multiple
    original_all = token_list._list._db.all
    original_check = token_list._list.check

    def blocked_insert_multiple(documents):
        first_db_call_started.set()
        release_first_db_call.wait()
        return original_insert_multiple(documents)

    def tracked_all():
        if first_db_call_started.is_set():
            second_db_call_started.set()
        return original_all()

    def tracked_check(token):
        second_worker_started.set()
        return original_check(token)

    token_list._list._db.insert_multiple = blocked_insert_multiple
    token_list._list._db.all = tracked_all
    token_list._list.check = tracked_check

    first = asyncio.create_task(token_list.add("first"))
    assert await asyncio.to_thread(first_db_call_started.wait, 1)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    second = asyncio.create_task(token_list.check("second"))
    assert await asyncio.to_thread(second_worker_started.wait, 1)
    assert not second_db_call_started.is_set()

    release_first_db_call.set()
    assert not await second
    await token_list.aclose()


@pytest.mark.asyncio
async def test_async_json_retries_failed_close(tmp_path):
    token_list = AsyncJSONList(
        type="black",
        json_path=str(tmp_path / "tokens.json"),
    )
    close = Mock(side_effect=[RuntimeError("close failed"), None])
    token_list._list.close = close

    with pytest.raises(RuntimeError, match="close failed"):
        await token_list.aclose()
    await token_list.aclose()

    assert close.call_count == 2


@pytest.mark.parametrize("backend", ["redis", "json"])
def test_malformed_batch_creates_no_persistent_entry(backend, tmp_path):
    if backend == "redis":
        token_list = RedisList(
            type="black",
            redis=FakeRedis(decode_responses=True),
        )
    else:
        token_list = JSONList(
            type="black",
            json_path=str(tmp_path / "tokens.json"),
        )

    with pytest.raises(JamValidationError):
        token_list.add_many(["valid", ""])

    assert not token_list.check("valid")


def test_list_logs_do_not_contain_token_or_fingerprint(tmp_path, caplog):
    fingerprint = token_fingerprint(TOKEN)
    token_list = JSONList(
        type="black",
        prefix="security",
        json_path=str(tmp_path / "tokens.json"),
    )

    with caplog.at_level("DEBUG"):
        token_list.add(TOKEN)
        token_list.check(TOKEN)
        token_list.delete(TOKEN)

    assert TOKEN not in caplog.text
    assert fingerprint not in caplog.text
