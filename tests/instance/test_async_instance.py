# -*- coding: utf-8 -*-

from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from fakeredis import FakeAsyncRedis

from jam.aio import AsyncJam, Jam
from jam.aio.lists.memory import MemoryList
from jam.authz import Principal
from jam.exceptions import (
    JamConfigurationError,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamTokenInDenyList,
    JamTokenNotInAllowList,
)
from jam.utils import generate_symmetric_key


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

    token = await jam.issue({"id": "user123"}, via="jwt")
    principal = await jam.authenticate(token=token, via="jwt")

    assert isinstance(token, str)
    assert isinstance(principal, Principal)
    assert principal.subject["id"] == "user123"
    assert principal.token_type == "jwt"


@pytest.mark.asyncio
async def test_issue_rejects_jwe():
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

    with pytest.raises(
        JamConfigurationError,
        match="Unknown 'via' type: jwe",
    ):
        await jam.issue(
            {"id": "user123"},
            via=cast(Any, "jwe"),
        )


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

    token = await jam.issue({"id": "user123"}, via="jwt")

    assert await jam.jwt_list.check(token)
    assert (await jam.authenticate(token, via="jwt")).subject["id"] == "user123"


@pytest.mark.asyncio
async def test_paseto_async_allowlist():
    key = generate_symmetric_key(32)
    jam = AsyncJam(
        config={
            "paseto": {
                "version": "v4",
                "purpose": "local",
                "secret_key": key,
                "list": {
                    "backend": "memory",
                    "type": "white",
                },
            }
        }
    )

    token = await jam.issue({"id": "user123"}, via="paseto")

    assert await jam.paseto_list.check(token)
    assert (
        await jam.authenticate(token, via="paseto")
    ).subject["id"] == "user123"

    await jam.paseto_list.delete(token)
    with pytest.raises(JamJWTNotInWhiteList):
        await jam.authenticate(token, via="paseto")


@pytest.mark.asyncio
async def test_paseto_async_denylist():
    jam = AsyncJam(
        config={
            "paseto": {
                "version": "v4",
                "purpose": "local",
                "secret_key": generate_symmetric_key(32),
                "list": {
                    "backend": "memory",
                    "type": "black",
                },
            }
        }
    )

    token = await jam.issue({"id": "user123"}, via="paseto")
    await jam.paseto_list.add(token)

    with pytest.raises(JamJWTInBlackList):
        await jam.authenticate(token, via="paseto")


@pytest.mark.asyncio
async def test_jwt_and_paseto_share_named_async_token_list():
    jam = AsyncJam(
        config={
            "lists": {
                "credentials": {
                    "backend": "memory",
                    "type": "white",
                }
            },
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "SECRET",
                    "list": "credentials",
                }
            },
            "paseto": {
                "version": "v4",
                "purpose": "local",
                "secret_key": generate_symmetric_key(32),
                "list": "credentials",
            },
        }
    )

    jwt = await jam.issue({"id": "jwt-user"}, via="jwt")
    paseto = await jam.issue({"id": "paseto-user"}, via="paseto")
    token_list = jam.lists["credentials"]

    assert jam.jwt_list is token_list
    assert jam.paseto_list is token_list
    assert await token_list.check_many([jwt, paseto]) == {
        jwt: True,
        paseto: True,
    }
    assert (
        await jam.authenticate(jwt, via="jwt")
    ).subject["id"] == "jwt-user"
    assert (
        await jam.authenticate(paseto, via="paseto")
    ).subject["id"] == "paseto-user"


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
    principal = await jam.authenticate(session_id, via="session")

    assert principal.subject["id"] == "user123"
    assert principal.token_type == "session"

    await jam.session.delete(session_id)
    assert await jam.session.get(session_id) is None


@pytest.mark.asyncio
async def test_aclose_closes_each_named_list_once():
    token_list = MemoryList(type="black")
    token_list.aclose = AsyncMock()
    jam = AsyncJam(
        config={
            "lists": {
                "first": token_list,
                "second": token_list,
            }
        }
    )

    await jam.aclose()

    token_list.aclose.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_saml_issue_and_authenticate(saml_configs):
    idp_config, sp_config = saml_configs
    idp = AsyncJam(config=idp_config)
    sp = AsyncJam(config=sp_config)

    token = await idp.issue(
        {"id": "user123", "role": "admin"},
        via="saml",
        exp=60,
    )
    principal = await sp.authenticate(token, via="saml")

    assert principal.subject["id"] == "user123"
    assert principal.claims["role"] == "admin"
    assert principal.claims["aud"] == "https://sp.test"
    assert principal.claims["iss"] == "https://idp.test"
    assert principal.token_type == "saml"


@pytest.mark.asyncio
async def test_saml_shared_async_allowlist(saml_configs):
    idp_config, sp_config = saml_configs
    token_list = MemoryList(type="white")
    list_config = {"credentials": token_list}
    idp = AsyncJam(
        config={
            "lists": list_config,
            "saml": {**idp_config["saml"], "list": "credentials"},
        }
    )
    sp = AsyncJam(
        config={
            "lists": list_config,
            "saml": {**sp_config["saml"], "list": "credentials"},
        }
    )

    token = await idp.issue({"id": "user123"}, via="saml", exp=60)

    assert idp.saml_list is token_list
    assert sp.saml_list is token_list
    assert await token_list.check(token)
    principal = await sp.authenticate(token, via="saml")
    assert principal.subject["id"] == "user123"

    await token_list.delete(token)
    with pytest.raises(JamTokenNotInAllowList):
        await sp.authenticate(token, via="saml")


@pytest.mark.asyncio
async def test_macaroon_shared_async_allowlist():
    jam = AsyncJam(
        config={
            "lists": {
                "credentials": {
                    "backend": "memory",
                    "type": "white",
                }
            },
            "keychains": {
                "root": {
                    "type": "Memory",
                    "algorithm": "MACAROON-HMAC-SHA256",
                }
            },
            "macaroon": {
                "keychain": "root",
                "list": "credentials",
            },
        }
    )
    jam.keychains["root"].rotate("first")

    token = await jam.issue({"id": "user123"}, via="macaroon")

    assert jam.macaroon_list is jam.lists["credentials"]
    assert await jam.lists["credentials"].check(token)
    principal = await jam.authenticate(token, via="macaroon")
    assert principal.subject["id"] == "user123"

    await jam.lists["credentials"].delete(token)
    with pytest.raises(JamTokenNotInAllowList):
        await jam.authenticate(token, via="macaroon")


@pytest.mark.asyncio
async def test_macaroon_shared_async_denylist():
    jam = AsyncJam(
        config={
            "lists": {
                "credentials": {
                    "backend": "memory",
                    "type": "black",
                }
            },
            "keychains": {
                "root": {
                    "type": "Memory",
                    "algorithm": "MACAROON-HMAC-SHA256",
                }
            },
            "macaroon": {
                "keychain": "root",
                "list": "credentials",
            },
        }
    )
    jam.keychains["root"].rotate("first")
    token = await jam.issue({"id": "user123"}, via="macaroon")

    assert not await jam.lists["credentials"].check(token)
    await jam.lists["credentials"].add(token)

    with pytest.raises(JamTokenInDenyList):
        await jam.authenticate(token, via="macaroon")
