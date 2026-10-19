"""Public downstream test helpers preserve payloads and failure contracts."""

import base64
import json
from urllib.parse import urlparse, parse_qs

import pytest

from jam.exceptions import (
    JamPASETOInvalidTokenFormat,
    JamSessionNotFound,
    JamJWSVerificationError,
    JamJWEDecryptionError,
)
from jam.tests import fakers
from jam.tests.clients import (
    TestJam,
    TestAsyncJam,
    FakePaseto,
    FakeOTP,
    FakeOAuth2Client,
    AsyncFakeOAuth2Client,
    FakeJWS,
    FakeJWE,
)


def decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def test_token_fakers_preserve_input_and_do_not_use_crypto():
    payload = {"sub": "user", "custom": "value"}
    with pytest.warns(DeprecationWarning):
        token = fakers.fake_jwt_token(payload)
    assert json.loads(decode(token.split(".")[1])) == payload
    token = fakers.fake_jwt_token_v2(
        sub="user", exp=123, header={"kid": "test"}
    )
    header, encoded, signature = token.split(".")
    assert json.loads(decode(header))["kid"] == "test"
    assert json.loads(decode(encoded)) == {"sub": "user", "exp": 123}
    assert signature == "fake_signature"
    assert fakers.invalid_token().startswith("INVALID_")
    assert fakers.generate_session_id().startswith("fake-session-")
    for function, prefix in [
        (fakers.fake_oauth2_token, "VALID_OAUTH2_TOKEN:"),
        (fakers.invalid_oauth2_token, "INVALID_OAUTH2_TOKEN:"),
    ]:
        encrypted = bytes.fromhex(function())
        key = b"JAM_FAKE"
        assert (
            bytes(
                value ^ key[i % len(key)] for i, value in enumerate(encrypted)
            )
            .decode()
            .startswith(prefix)
        )


@pytest.mark.parametrize("value", [{"sub": "u"}, "text", None])
def test_jws_and_jwe_fakers(value):
    for function in (fakers.fake_jws_token, fakers.fake_jwe_token):
        token = function(value, header={"kid": "test"})
        segments = token.split(".")
        assert json.loads(decode(segments[0]))["kid"] == "test"
        if isinstance(value, dict):
            assert json.loads(decode(segments[1])) == value
        elif value is not None:
            assert decode(segments[1]).decode() == value


@pytest.mark.parametrize("footer", [None, {"kid": "test"}, "text", b"bytes"])
def test_paseto_helpers(footer):
    token = fakers.fake_paseto_token({"sub": "u"}, footer=footer)
    assert json.loads(decode(token.split(".")[2])) == {"sub": "u"}
    helper = FakePaseto()
    token = helper.encode({"sub": "u"}, footer=footer)
    payload, decoded_footer = helper.decode(token)
    assert payload == {"sub": "u"}
    assert decoded_footer == (
        footer.decode() if isinstance(footer, bytes) else footer
    )
    with pytest.raises(JamPASETOInvalidTokenFormat):
        helper.decode("invalid")


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
async def test_testing_facade_jwe_and_session_rotation(async_):
    jam = TestAsyncJam() if async_ else TestJam()
    if async_:
        token = await jam.issue({"id": "u"}, via="jwe", exp=60)
        assert (await jam.authenticate(token, via="jwe")).subject["id"] == "u"
        session = await jam.session.create("auth", {})
        await jam.session.update(session, {"id": "u"})
        replacement = await jam.session.rework(session)
        assert await jam.session.get(session) is None
        await jam.session.clear("auth")
        assert await jam.session.get(replacement) is None
    else:
        token = jam.issue({"id": "u"}, via="jwe", exp=60)
        assert jam.authenticate(token, via="jwe").subject["id"] == "u"
        with pytest.raises(JamSessionNotFound):
            jam.session.update("missing", {})
        with pytest.raises(JamSessionNotFound):
            jam.session.rework("missing")
    assert jam.policy is not None


@pytest.mark.asyncio
async def test_fake_oauth_and_otp_contracts():
    sync, async_ = FakeOAuth2Client(), AsyncFakeOAuth2Client()
    for client in (sync, async_):
        for method, argument in [
            ("fetch_token", "code"),
            ("refresh_token", "refresh"),
            ("client_credentials_flow", ["profile"]),
        ]:
            result = getattr(client, method)(argument)
            if client is async_:
                result = await result
            result["access_token"] = "changed"
            assert client.token["access_token"] != "changed"
    assert "scope=profile" in sync.get_authorization_url(["profile"])
    assert "scope=profile" in await async_.get_authorization_url(["profile"])
    otp = FakeOTP()
    assert otp.at(5) == otp.now()
    assert otp.verify(otp.now()) and not otp.verify("bad")
    uri = otp.provisioning_uri("user", "issuer", type_="hotp", counter=7)
    assert parse_qs(urlparse(uri).query)["counter"] == ["7"]


def test_fake_crypto_rejects_malformed_input():
    with pytest.raises(JamJWSVerificationError):
        FakeJWS().verify("malformed")
    with pytest.raises(JamJWEDecryptionError):
        FakeJWE().decrypt("malformed")
