# -*- coding: utf-8 -*-

from typing import Any

import flask

from jam.exceptions import JamFlaskPluginConfigError
from jam.jose import create_instance as create_jwt
from jam.oauth2 import create_instance as create_oauth2
from jam.paseto import create_instance as create_paseto
from jam.sessions import create_instance as create_session
from jam.utils.config_maker import GENERIC_POINTER, __config_maker__


class BaseExtension:
    """Base Jam extension for Flask."""

    MODULE: Any
    _CONFIG_KEY: str

    def __init__(
        self,
        app: flask.Flask | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the extension.

        Args:
            app (flask.Flask | None): Flask application instance
            **kwargs: Configuration arguments
        """
        self.app = app
        self._config = kwargs
        if app is not None:
            self.init_app(app)

    def init_app(self, app: flask.Flask) -> None:
        """Initialize the Flask application.

        Args:
            app (flask.Flask): Flask application instance
        """
        self.app = app
        self._auth = self.MODULE(**self._config)
        app.extensions[self._CONFIG_KEY] = self._auth


class BaseAuthExtension(BaseExtension):
    """Base Jam authentication extension for Flask."""

    MODULE: Any
    _CONFIG_KEY: str

    def __init__(
        self,
        app: flask.Flask | None = None,
        config: dict[str, Any] | str | None = None,
        pointer: str = GENERIC_POINTER,
        cookie_name: str | None = None,
        header_name: str | None = None,
        bearer: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize the authentication extension.

        Args:
            app (flask.Flask | None): Flask application instance
            config (dict[str, Any] | str | None): Jam config as path/to/file or dict.
            pointer (str): Config pointer
            cookie_name (str | None): Cookie name to read token
            header_name (str | None): Header name to read token
            bearer (bool): Strip "Bearer " prefix from header
            **kwargs: Configuration arguments if config=None
        """
        self._cookie_name = cookie_name
        self._header_name = header_name
        self._bearer = bearer

        if not cookie_name and not header_name:
            raise JamFlaskPluginConfigError(
                message="Cookie name and header name cannot be both None.",
                details={
                    "cookie_name": cookie_name,
                    "header_name": header_name,
                },
            )

        _config: dict[str, Any] | None = (
            __config_maker__(config, pointer) if config else None
        )
        if _config and _config.get("jose", None) and self.MODULE == create_jwt:
            _config = _config["jose"]

        params = _config.pop(self._CONFIG_KEY) if _config else kwargs
        super().__init__(app=app, **params)

    def _get_token(self) -> str | None:
        token = None
        if self._header_name:
            token = flask.request.headers.get(self._header_name, None)
            if token and self._bearer and token.startswith("Bearer "):
                token = token[7:]
        elif self._cookie_name:
            token = flask.request.cookies.get(self._cookie_name, None)
        return token

    def _get_payload(self) -> dict[str, Any] | None:
        raise NotImplementedError

    def init_app(self, app: flask.Flask) -> None:
        """Initialize the Flask application."""
        super().init_app(app)
        app.before_request(self._put_auth_in_g)

    def _put_auth_in_g(self) -> None:
        setattr(flask.g, self._CONFIG_KEY, self._auth)
        self._get_payload()


class JWTExtension(BaseAuthExtension):
    """JWT extension for Flask."""

    MODULE = staticmethod(create_jwt)
    _CONFIG_KEY = "jwt"

    def __init__(
        self,
        app: flask.Flask | None = None,
        config: dict[str, Any] | str | None = None,
        pointer: str = GENERIC_POINTER,
        cookie_name: str | None = None,
        header_name: str | None = None,
        use_list: bool = False,
        bearer: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize the authentication extension.

        Args:
            app (flask.Flask | None): Flask application instance
            config (dict[str, Any] | str | None): Jam config as path/to/file or dict.
            pointer (str): Config pointer
            cookie_name (str | None): Cookie name to read token
            header_name (str | None): Header name to read token
            use_list (bool): Use a list for token
            bearer (bool): Strip "Bearer " prefix from header
            **kwargs: Configuration arguments if config=None
        """
        self._use_list = use_list
        super().__init__(
            app=app,
            config=config,
            pointer=pointer,
            cookie_name=cookie_name,
            header_name=header_name,
            bearer=bearer,
            **kwargs,
        )

    def _get_payload(self) -> dict[str, Any] | None:
        token = self._get_token()
        if self._use_list:
            match self._auth.list.__list_type__:
                case "black":
                    if self._auth.list.check(token):
                        return None
                case "white":
                    if not self._auth.list.check(token):
                        return None
        flask.g.payload = None
        if not token:
            return None
        try:
            result = self._auth.decode(token)
            payload = result.get("payload", result)
            flask.g.payload = payload
            return payload
        except Exception:
            return None


class SessionExtension(BaseAuthExtension):
    """Session extension for Flask."""

    MODULE = staticmethod(create_session)
    _CONFIG_KEY = "sessions"

    def _get_payload(self) -> dict[str, Any] | None:
        token = self._get_token()
        flask.g.payload = None
        if not token:
            return None
        try:
            payload = self._auth.get(token)
            flask.g.payload = payload
            return payload
        except Exception:
            return None


class PASETOExtension(BaseAuthExtension):
    """PASETO extension for Flask."""

    MODULE = staticmethod(create_paseto)
    _CONFIG_KEY = "paseto"

    def _get_payload(self) -> dict[str, Any] | None:
        token = self._get_token()
        flask.g.payload = None
        if not token:
            return None
        try:
            data = self._auth.decode(token)
            if not data:
                return None
            payload = data[0] if isinstance(data, tuple) else data
            flask.g.payload = payload
            return payload
        except Exception:
            return None


class OAuth2Extension(BaseExtension):
    """OAuth2 extension for Flask."""

    MODULE = staticmethod(create_oauth2)
    _CONFIG_KEY = "oauth2"

    def __init__(
        self,
        app: flask.Flask | None = None,
        config: dict[str, Any] | str | None = None,
        pointer: str = GENERIC_POINTER,
        **kwargs: Any,
    ) -> None:
        """Initialize the OAuth2 extension.

        Args:
            app (flask.Flask | None): Flask application instance
            config (dict[str, Any] | str | None): Jam config as path/to/file or dict.
            pointer (str): Config pointer
            **kwargs: Configuration arguments if config=None
        """
        _config: dict[str, Any] | None = (
            __config_maker__(config, pointer) if config else None
        )

        params = _config.pop(self._CONFIG_KEY) if _config else kwargs
        super().__init__(app, **params)
