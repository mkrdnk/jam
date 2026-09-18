# -*- coding: utf-8 -*-

from contextlib import contextmanager
from http.client import HTTPSConnection
import json
import logging
from typing import Any
import urllib.parse

from jam.exceptions import JamOAuth2EmptyRaw, JamOAuth2Error

from .__base__ import BaseOAuth2Client


logger = logging.getLogger(__name__)


class OAuth2Client(BaseOAuth2Client):
    """Universal OAuth2 client implementation."""

    @contextmanager
    def __http(self, url: str):
        """Create HTTPS connection context manager."""
        parsed = urllib.parse.urlparse(url)
        connection = HTTPSConnection(parsed.netloc)
        try:
            yield connection, parsed
        finally:
            connection.close()

    def get_authorization_url(
        self, scope: list[str], **extra_params: Any
    ) -> str:
        """Generate full OAuth2 authorization URL.

        Args:
            scope (list[str]): Auth scope
            extra_params (Any): Extra ath params

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
        logger.debug(
            "Built OAuth2 authorization URL with scope_count=%d",
            len(scope),
        )
        return f"{self.auth_url}?{urllib.parse.urlencode(params)}"

    def fetch_token(
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

        return self.__post_form(self.token_url, body)

    def refresh_token(
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

        return self.__post_form(self.token_url, body)

    def client_credentials_flow(
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

        return self.__post_form(self.token_url, body)

    def __post_form(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send POST form and parse JSON response."""
        encoded = urllib.parse.urlencode(params)
        parsed_url = urllib.parse.urlparse(url)
        grant_type = params.get("grant_type", "unknown")
        logger.debug(
            "Sending OAuth2 token request with grant_type=%s to %s%s",
            grant_type,
            parsed_url.netloc,
            parsed_url.path,
        )

        with self.__http(url) as (conn, parsed):
            conn.request(
                "POST",
                parsed.path,
                body=encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = conn.getresponse()
            raw = response.read().decode("utf-8")

        if not raw:
            logger.error(
                "OAuth2 token endpoint returned an empty response for grant_type=%s",
                grant_type,
            )
            raise JamOAuth2EmptyRaw(
                details={"endpoint": url, "methid": "POST", "params": params}
            )

        try:
            data = self._serializer.loads(raw)
        except (json.JSONDecodeError, AttributeError):
            data = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

        if response.status >= 400:
            logger.warning(
                "OAuth2 token request failed with status=%d for grant_type=%s",
                response.status,
                grant_type,
            )
            raise JamOAuth2Error(
                details={
                    "status": response.status,
                    "reason": response.reason,
                    "data": data,
                }
            )

        logger.debug(
            "OAuth2 token request completed with status=%d for grant_type=%s",
            response.status,
            grant_type,
        )
        return data
