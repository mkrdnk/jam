# -*- coding: utf-8 -*-

import pytest
from fakeredis import FakeAsyncRedis, FakeRedis

from jam.aio.lists.json import AsyncJSONList
from jam.aio.lists.memory import MemoryList as AsyncMemoryList
from jam.aio.lists.redis import RedisList as AsyncRedisList
from jam.exceptions import (
    JamConfigurationError,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamTokenInDenyList,
    JamTokenNotInAllowList,
)
from jam.lists import build_list
from jam.lists.json import JSONList
from jam.lists.memory import MemoryList
from jam.lists.redis import RedisList


@pytest.fixture(params=("memory", "json", "redis"))
def token_list(request, tmp_path):
    if request.param == "memory":
        return MemoryList(type="black")
    if request.param == "json":
        return JSONList(
            type="black",
            json_path=str(tmp_path / "tokens.json"),
        )
    return RedisList(
        type="black",
        redis_uri=FakeRedis(decode_responses=True),
    )


def test_sync_backend_contract(token_list):
    token_list.add_many([])
    assert token_list.check_many([]) == {}
    token_list.delete_many([])

    token_list.add("one")
    token_list.add_many(["two", "three"])

    assert token_list.check("one")
    assert token_list.check_many(["one", "missing"]) == {
        "one": True,
        "missing": False,
    }

    token_list.delete("one")
    token_list.delete_many(["two", "three"])

    assert not token_list.check("one")
    assert token_list.check_many(["two", "three"]) == {
        "two": False,
        "three": False,
    }

    special_tokens = ["токен", "x" * 10_000]
    token_list.add_many([*special_tokens, special_tokens[0]])
    assert token_list.check_many(special_tokens) == {
        token: True for token in special_tokens
    }
    token_list.delete_many([*special_tokens, special_tokens[0]])
    token_list.delete_many(special_tokens)
    assert token_list.check_many(special_tokens) == {
        token: False for token in special_tokens
    }


@pytest.fixture(params=("memory", "json", "redis"))
def async_token_list(request, tmp_path):
    if request.param == "memory":
        return AsyncMemoryList(type="black")
    if request.param == "json":
        return AsyncJSONList(
            type="black",
            json_path=str(tmp_path / "tokens.json"),
        )
    return AsyncRedisList(
        type="black",
        redis_uri=FakeAsyncRedis(decode_responses=True),
    )


@pytest.mark.asyncio
async def test_async_backend_contract(async_token_list):
    await async_token_list.add_many([])
    assert await async_token_list.check_many([]) == {}
    await async_token_list.delete_many([])

    await async_token_list.add("one")
    await async_token_list.add_many(["two", "three"])

    assert await async_token_list.check("one")
    assert await async_token_list.check_many(["one", "missing"]) == {
        "one": True,
        "missing": False,
    }

    await async_token_list.delete("one")
    await async_token_list.delete_many(["two", "three"])

    assert not await async_token_list.check("one")
    assert await async_token_list.check_many(["two", "three"]) == {
        "two": False,
        "three": False,
    }

    special_tokens = ["токен", "x" * 10_000]
    await async_token_list.add_many([*special_tokens, special_tokens[0]])
    assert await async_token_list.check_many(special_tokens) == {
        token: True for token in special_tokens
    }
    await async_token_list.delete_many([*special_tokens, special_tokens[0]])
    await async_token_list.delete_many(special_tokens)
    assert await async_token_list.check_many(special_tokens) == {
        token: False for token in special_tokens
    }


@pytest.mark.parametrize(
    ("config", "error_code"),
    [
        ({"backend": "memory", "type": "other"}, "configuration.lists.unknown_type"),
        ({"type": "black"}, "configuration.lists.unknown_backend"),
    ],
)
def test_build_list_rejects_invalid_config(config, error_code):
    with pytest.raises(JamConfigurationError) as exc_info:
        build_list(config)

    assert exc_info.value.error_code == error_code


def test_legacy_jwt_list_errors_are_generic_aliases():
    assert JamJWTInBlackList is JamTokenInDenyList
    assert JamJWTNotInWhiteList is JamTokenNotInAllowList
