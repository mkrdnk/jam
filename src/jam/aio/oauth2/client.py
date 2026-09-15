# -*- coding: utf-8 -*-

import json
from typing import Any
import urllib.parse


try:
    import httpx
except ImportError:
    raise ImportError(
        "Async OAuth2 support requires 'pip install jamlib[oauth2]'."
    )

from jam.aio.oauth2.__base__ import BaseAsyncOAuth2Client
from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamOAuth2EmptyRaw, JamOAuth2Error


class OAuth2Client(BaseAsyncOAuth2Client):
    """Async universal OAuth2 client implementation."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_url: str,
        token_url: str,
        redirect_url: str,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize the client with an optional user-owned HTTP client."""
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            auth_url=auth_url,
            token_url=token_url,
            redirect_url=redirect_url,
            serializer=serializer,
        )
        self._client = client or httpx.AsyncClient()
        self._owns_client = client is None

    def get_authorization_url(
        self, scope: list[str], **extra_params: Any
    ) -> str:
        """Generate full OAuth2 authorization URL.

        Args:
            scope (list[str]): Auth scope
            extra_params (Any): Extra auth params

        Returns:
            str: Authorization url
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_url,
            "response_type": "code",
            "scope": " ".join(scope),
        }
        params.update(
            extra_params
        )  # for example: access_type='offline', state='xyz'
        return f"{self.auth_url}?{urllib.parse.urlencode(params)}"

    async def fetch_token(
        self,
        code: str,
        grant_type: str = "authorization_code",
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Exchange authorization code for access token.

        Args:
            code (str): OAuth2 code
            grant_type (str): Type of oauth2 grant
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: OAuth2 token
        """
        body = {
            "client_id": self.client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": self.redirect_url,
            "grant_type": grant_type,
        }
        body.update(extra_params)

        return await self.__post_form(self.token_url, body)

    async def refresh_token(
        self,
        refresh_token: str,
        grant_type: str = "refresh_token",
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Use refresh token to obtain a new access token.

        Args:
            refresh_token (str): Refresh token
            grant_type (str): Grant type
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: Refresh token
        """
        body = {
            "client_id": self.client_id,
            "client_secret": self._client_secret,
            "refresh_token": refresh_token,
            "grant_type": grant_type,
        }
        body.update(extra_params)

        return await self.__post_form(self.token_url, body)

    async def client_credentials_flow(
        self, scope: list[str] | None = None, **extra_params: Any
    ) -> dict[str, Any]:
        """Obtain access token using client credentials flow (no user interaction).

        Args:
            scope (list[str] | None): Auth scope
            extra_params (Any): Extra auth params if needed

        Raises:
            JamOAuth2EmptyRaw: If response is empty
            JamOAuth2Error: HTTP error

        Returns:
            dict: JSON with access token
        """
        body = {
            "client_id": self.client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
        }
        if scope:
            body["scope"] = " ".join(scope)
        body.update(extra_params)

        return await self.__post_form(self.token_url, body)

    async def __post_form(
        self, url: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Send a non-blocking POST form request and parse its response."""
        response = await self._client.post(url, data=params)
        raw = response.text
        if not raw:
            raise JamOAuth2EmptyRaw(
                details={
                    "endpoint": url,
                    "method": "POST",
                    "params": params,
                }
            )

        try:
            data = self._serializer.loads(raw)
        except (json.JSONDecodeError, AttributeError):
            data = {
                key: value[0]
                for key, value in urllib.parse.parse_qs(raw).items()
            }

        if response.is_error:
            raise JamOAuth2Error(
                details={
                    "status": response.status_code,
                    "reason": response.reason_phrase,
                    "data": data,
                }
            )
        return data

    async def aclose(self) -> None:
        """Close the internally-created HTTP client."""
        if self._owns_client:
            await self._client.aclose()
