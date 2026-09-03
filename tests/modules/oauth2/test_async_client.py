# -*- coding: utf-8 -*-

import httpx
import pytest

from jam.aio.oauth2.client import OAuth2Client


def make_client(handler):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuth2Client(
        client_id="client",
        client_secret="secret",
        auth_url="https://provider.test/authorize",
        token_url="https://provider.test/token",
        redirect_url="https://app.test/callback",
        client=http,
    )
    return client, http


@pytest.mark.asyncio
async def test_authorization_url_is_synchronous():
    client, http = make_client(lambda request: httpx.Response(200, json={}))

    url = client.get_authorization_url(["profile"], state="state")

    assert "scope=profile" in url
    assert "state=state" in url
    await http.aclose()


@pytest.mark.asyncio
async def test_fetch_token_uses_async_transport():
    def handler(request):
        assert request.url == "https://provider.test/token"
        return httpx.Response(200, json={"access_token": "token"})

    client, http = make_client(handler)

    response = await client.fetch_token("code")

    assert response == {"access_token": "token"}
    await client.aclose()
    assert not http.is_closed
    await http.aclose()
