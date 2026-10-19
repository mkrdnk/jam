"""JWE list enforcement through both facades and the standalone JWT API."""

import inspect

import pytest

from jam import Jam
from jam.aio import AsyncJam
from jam.exceptions import (
    JamConfigurationError,
    JamJWTExpired,
    JamJWTNotYetValid,
    JamTokenInDenyList,
    JamTokenNotInAllowList,
    JamError,
)
from jam.jose import JWT


def config(kind=None):
    jwt = {"alg": "HS256", "enc": "A256GCM", "secret_key": "x" * 32}
    if kind:
        jwt["list"] = {"backend": "memory", "type": kind}
    return {"jose": {"jwt": jwt}}


async def call(method, *args, **kwargs):
    result = method(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [Jam, AsyncJam])
@pytest.mark.parametrize("kind", [None, "white", "black"])
async def test_jwe_issue_authenticate_and_revoke(cls, kind):
    jam = cls(config=config(kind))
    token = await call(
        jam.issue,
        {"id": "u"},
        via="jwe",
        exp=60,
        iss="issuer",
        aud="audience",
        jti="fixed",
        permissions=["read"],
        custom="value",
    )
    principal = await call(jam.authenticate, token, via="jwe")
    assert principal.subject["id"] == "u"
    assert principal.token_type == "jwe"
    assert principal.claims["permissions"] == ["read"]
    assert principal.claims["iss"] == "issuer"
    assert principal.claims["aud"] == "audience"
    assert principal.claims["jti"] == "fixed"
    assert principal.claims["custom"] == "value"
    assert principal.claims["exp"] - principal.claims["iat"] == 60
    if kind == "white":
        assert await call(jam.jwt_list.check, token)
        inner = jam.jwt.jwe.decrypt(token)
        assert not await call(
            jam.jwt_list.check,
            inner.decode() if isinstance(inner, bytes) else inner,
        )
        await call(jam.jwt_list.delete, token)
        with pytest.raises(JamTokenNotInAllowList) as error:
            await call(jam.authenticate, token, via="jwe")
        assert error.value.error_code == "jwt.whitelist"
    elif kind == "black":
        await call(jam.jwt_list.add, token)
        with pytest.raises(JamTokenInDenyList) as error:
            await call(jam.authenticate, token, via="jwe")
        assert error.value.error_code == "jwt.blacklist"


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [Jam, AsyncJam])
@pytest.mark.parametrize(
    "claim,error",
    [({"exp": 0}, JamJWTExpired), ({"nbf": 60}, JamJWTNotYetValid)],
)
async def test_jwe_registered_times(cls, claim, error):
    jam = cls(config=config("white"))
    token = await call(jam.issue, {"id": "u"}, via="jwe", **claim)
    with pytest.raises(error):
        await call(jam.authenticate, token, via="jwe")


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [Jam, AsyncJam])
async def test_unsigned_jwe_cannot_be_issued_as_credential(cls):
    jam = cls(
        config={"jose": {"jwt": {"enc": "A256GCM", "secret_key": "x" * 32}}}
    )
    with pytest.raises(JamConfigurationError) as error:
        await call(jam.issue, {"id": "u"}, via="jwe")
    assert (
        error.value.error_code
        == "configuration.jwe.authentication_requires_jws"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [Jam, AsyncJam])
async def test_jwe_registration_failure_is_not_success(cls, monkeypatch):
    jam = cls(config=config("white"))

    def fail(token):
        raise RuntimeError("storage unavailable")

    async def afail(token):
        fail(token)

    monkeypatch.setattr(jam.jwt_list, "add", afail if cls is AsyncJam else fail)
    with pytest.raises(RuntimeError, match="storage unavailable"):
        await call(jam.issue, {"id": "u"}, via="jwe")


@pytest.mark.parametrize("kind", ["white", "black"])
def test_standalone_encrypt_decrypt_lists(kind):
    jwt = JWT(config=config(kind)["jose"]["jwt"])
    token = jwt.encrypt({"sub": "u"})
    assert jwt.decrypt(token) == {"sub": "u"}
    if kind == "white":
        jwt.list.delete(token)
        error = JamTokenNotInAllowList
    else:
        jwt.list.add(token)
        error = JamTokenInDenyList
    with pytest.raises(error):
        jwt.decrypt(token)
    assert jwt.decrypt(token, check_list=False) == {"sub": "u"}


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [Jam, AsyncJam])
async def test_allowed_jwe_still_requires_valid_crypto(cls):
    jam = cls(config=config("white"))
    other = JWT(alg="HS256", enc="A256GCM", secret_key="y" * 32)
    for token in (other.encrypt({"sub": "u"}), "malformed"):
        await call(jam.jwt_list.add, token)
        with pytest.raises(JamError):
            await call(jam.authenticate, token, via="jwe")


def test_zero_expiry_is_also_enforced_for_jwt():
    jwt = JWT(alg="HS256", secret_key="x" * 32)
    with pytest.raises(JamJWTExpired):
        jwt.decode(jwt.encode(exp=0))


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [Jam, AsyncJam])
async def test_jwe_configuration_error_precedes_list_rejection(cls):
    cfg = config("white")
    del cfg["jose"]["jwt"]["enc"]
    jam = cls(config=cfg)
    with pytest.raises(JamConfigurationError) as error:
        await call(jam.authenticate, "not-listed", via="jwe")
    assert error.value.error_code == "configuration.jwe.not_configured"


def test_jwe_rejects_invalid_custom_list_type():
    jwt = JWT(config=config("white")["jose"]["jwt"])
    token = jwt.encrypt({"sub": "u"})
    jwt.list.__list_type__ = "unknown"
    with pytest.raises(JamConfigurationError) as error:
        jwt.decrypt(token)
    assert error.value.error_code == "configuration.jwt.unknown_list_type"
