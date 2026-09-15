# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from collections.abc import Callable
from secrets import token_urlsafe
from typing import Any

from jam.encoders import BaseEncoder, JsonEncoder
from jam.utils.config_meta import ConfigMeta


class BaseOAuth2Client(ABC, metaclass=ConfigMeta):
    """Base OAuth2 client instance."""

    _CONFIG_POINTER: str = "jam.oauth2"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_url: str,
        token_url: str,
        redirect_url: str,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Constructor.

        Args:
            client_id (str): ID or your client
            client_secret (str): Secret key for your application
            auth_url (str): App auth url
            token_url (str): App token url
            redirect_url (str): Your app url
            serializer (Union[BaseEncoder, type[BaseEncoder]], optional): JSON encoder/decoder. Defaults to JsonEncoder.
            config (str | dict[str, Any] | None): Configuration dict or file path.
            pointer (str | None): Config pointer. Defaults to "jam.oauth2".
        """
        self.client_id = client_id
        self._client_secret = client_secret
        self.auth_url = auth_url
        self.token_url = token_url
        self.redirect_url = redirect_url
        self._serializer = serializer

    @abstractmethod
    def get_authorization_url(self, scope: list[str]) -> str:
        """Get OAuth2 url.

        Args:
            scope (list[str]): Auth scope

        Returns:
            str: URL for auth
        """
        raise NotImplementedError

    @abstractmethod
    def fetch_token(
        self, code: str, grant_type: str = "authorization_code"
    ) -> dict[str, Any]:
        """Exchange code for access token.

        Args:
            code (str): Auth code
            grant_type (str): Grant type

        Returns:
            dict: OAuth2 token response
        """
        raise NotImplementedError

    @abstractmethod
    def refresh_token(
        self, refresh_token: str, grant_type: str = "refresh_token"
    ) -> dict[str, Any]:
        """Update access token.

        Args:
            refresh_token (str): Refresh token
            grant_type (str): Grant type

        Returns:
            dict: New token response
        """
        raise NotImplementedError

    @abstractmethod
    def client_credentials_flow(
        self, scope: list[str] | None = None
    ) -> dict[str, Any]:
        """Obtain access token using client credentials flow (no user interaction).

        Args:
            scope (Optional[list[str]]): Auth scope

        Returns:
            dict: JSON with access token
        """
        raise NotImplementedError


class __BaseOAuth2Server(ABC):
    """Base OAuth2 server instance."""

    def __init__(
        self,
        app_url: str,
        code_factory: Callable[[], str] = lambda: token_urlsafe(8),
    ) -> None:
        """Constructor.

        Args:
            app_url (str): URL of your app
            code_factory (Callable[[] ,str]): Factory for code generation
        """
        self.app_url = app_url
        self.code_factory = code_factory
        raise NotImplementedError("Not implemented in the current version!")

    @property
    def code(self) -> str:
        return self.code_factory()

    ...
