# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any

from jam.encoders import BaseEncoder, JsonEncoder


class BaseAsyncOAuth2Client(ABC):
    """Base async OAuth2 client instance."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_url: str,
        token_url: str,
        redirect_url: str,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
    ) -> None:
        """Constructor.

        Args:
            client_id (str): ID or your client
            client_secret (str): Secret key for your application
            auth_url (str): App auth url
            token_url (str): App token url
            redirect_url (str): Your app url
            serializer (Union[BaseEncoder, type[BaseEncoder]], optional): JSON encoder/decoder. Defaults to JsonEncoder.
        """
        self.client_id = client_id
        self._client_secret = client_secret
        self.auth_url = auth_url
        self.token_url = token_url
        self.redirect_url = redirect_url
        self._serializer = serializer

    @abstractmethod
    def get_authorization_url(
        self, scope: list[str], **extra_params: Any
    ) -> str:
        """Get OAuth2 url.

        Args:
            scope (list[str]): Auth scope
            extra_params (Any): Extra auth params

        Returns:
            str: URL for auth
        """
        raise NotImplementedError

    @abstractmethod
    async def fetch_token(
        self,
        code: str,
        grant_type: str = "authorization_code",
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Exchange code for access token.

        Args:
            code (str): Auth code
            grant_type (str): Type of oauth2 grant
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: OAuth2 token response
        """
        raise NotImplementedError

    @abstractmethod
    async def refresh_token(
        self,
        refresh_token: str,
        grant_type: str = "refresh_token",
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Update access token.

        Args:
            refresh_token (str): Refresh token
            grant_type (str): Grant type
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: New token response
        """
        raise NotImplementedError

    @abstractmethod
    async def client_credentials_flow(
        self, scope: list[str] | None = None, **extra_params: Any
    ) -> dict[str, Any]:
        """Obtain access token using client credentials flow (no user interaction).

        Args:
            scope (list[str] | None): Auth scope
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: JSON with access token
        """
        raise NotImplementedError
