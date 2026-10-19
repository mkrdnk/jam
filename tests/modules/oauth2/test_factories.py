"""Factory wiring and async OAuth2 error/ownership contracts."""

import copy
from urllib.parse import parse_qs

import httpx
import pytest

from jam import Jam
from jam.aio import AsyncJam
from jam.aio.oauth2.client import OAuth2Client
from jam.exceptions import JamOAuth2EmptyRaw, JamOAuth2Error


@pytest.mark.asyncio
@pytest.mark.parametrize("async_", [False, True])
@pytest.mark.parametrize(
    "provider", ["github", "gitlab", "google", "yandex", "custom", "generic"]
)
async def test_provider_factory_and_ownership(async_, provider):
    options = {
        "client_id": "id",
        "client_secret": "secret",
        "redirect_url": "https://app.test/cb",
    }
    if provider in ("custom", "generic"):
        options.update(
            auth_url="https://provider.test/auth",
            token_url="https://provider.test/token",
        )
    if provider == "custom":
        options["custom_module"] = (
            "jam.aio.oauth2.client.OAuth2Client"
            if async_
            else "jam.oauth2.client.OAuth2Client"
        )
    cfg = {"oauth2": {provider: options}}
    original = copy.deepcopy(cfg)
    jam = (AsyncJam if async_ else Jam)(config=cfg)
    client = jam.oauth2[provider]
    assert cfg == original
    assert "client_id=id" in client.get_authorization_url(["profile"])
    assert client.redirect_url == "https://app.test/cb"
    if async_:
        await jam.aclose()
    else:
        jam.close()
    if async_:
        assert client._client.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation,expected",
    [
        ("refresh_token", "refresh_token"),
        ("client_credentials_flow", "client_credentials"),
    ],
)
async def test_async_grants_use_form_transport(operation, expected):
    def handler(request):
        form = parse_qs(request.content.decode())
        assert form["grant_type"] == [expected]
        assert form["client_id"] == ["id"]
        assert form["extra"] == ["value"]
        return httpx.Response(200, text="access_token=token&token_type=bearer")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as http:
        client = OAuth2Client(
            "id",
            "secret",
            "https://p.test/auth",
            "https://p.test/token",
            "https://a.test/cb",
            client=http,
        )
        args = ("refresh",) if operation == "refresh_token" else (["read"],)
        assert await getattr(client, operation)(*args, extra="value") == {
            "access_token": "token",
            "token_type": "bearer",
        }
        await client.aclose()
        assert not http.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,body,error",
    [
        (200, "", JamOAuth2EmptyRaw),
        (400, '{"error":"invalid_grant"}', JamOAuth2Error),
    ],
)
async def test_async_endpoint_failures(status, body, error):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, text=body)
        )
    ) as http:
        client = OAuth2Client(
            "id",
            "secret",
            "https://p.test/auth",
            "https://p.test/token",
            "https://a.test/cb",
            client=http,
        )
        with pytest.raises(error):
            await client.client_credentials_flow()
