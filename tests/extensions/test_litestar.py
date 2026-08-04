# -*- coding: utf-8 -*-
# ruff: noqa: D100, D101, D102, D103

from litestar.config.app import AppConfig
import pytest

pytestmark = pytest.mark.skip(
    "jam.ext is deferred until the module API rework is complete"
)

try:
    from jam.ext.litestar import (
        JWTPlugin,
        OAuth2Plugin,
        PASETOPlugin,
        SessionPlugin,
    )
    from jam.ext.litestar.objects import SimpleUser
except ImportError:
    pytest.skip(
        "jam.ext is deferred until the module API rework is complete",
        allow_module_level=True,
    )


@pytest.fixture
def middleware_user():
    return SimpleUser


@pytest.fixture
def jwt_config():
    return {"jose": {"jwt": {"secret": "test-secret", "alg": "HS256"}}}


@pytest.fixture
def session_config():
    return {"sessions": {"session_type": "json", "json_path": ":memory:"}}


@pytest.fixture
def paseto_config():
    return {
        "paseto": {
            "version": "v2",
            "purpose": "local",
            "secret_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE",
        }
    }


@pytest.fixture
def oauth2_config():
    return {
        "oauth2": {
            "providers": {
                "test": {
                    "custom_module": "jam.oauth2.client.OAuth2Client",
                    "client_id": "test",
                    "client_secret": "test-secret",
                    "redirect_url": "http://localhost",
                    "auth_url": "http://example.com/auth",
                    "token_url": "http://example.com/token",
                }
            }
        }
    }


class TestJamJWTPlugin:
    def test_adds_dependency(self, jwt_config, middleware_user):
        plugin = JWTPlugin(
            config=jwt_config,
            cookie_name="auth_token",
            header_name="Authorization",
            user=middleware_user,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert "jwt" in updated_config.dependencies
        provider = updated_config.dependencies["jwt"]
        assert callable(provider.dependency)

    def test_adds_middleware(self, jwt_config, middleware_user):
        plugin = JWTPlugin(
            config=jwt_config,
            cookie_name="auth_token",
            header_name="Authorization",
            user=middleware_user,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert len(updated_config.middleware) == 1

    def test_raises_error_when_no_cookie_or_header(
        self, jwt_config, middleware_user
    ):
        with pytest.raises(Exception):
            JWTPlugin(
                config=jwt_config,
                cookie_name=None,
                header_name=None,
                user=middleware_user,
            )

    def test_raises_error_when_no_middleware_user(self, jwt_config):
        with pytest.raises(Exception):
            JWTPlugin(
                config=jwt_config,
                cookie_name="auth_token",
                user=None,
            )

    def test_without_middleware(self, jwt_config):
        plugin = JWTPlugin(
            config=jwt_config,
            middleware=False,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert "jwt" in updated_config.dependencies
        assert len(updated_config.middleware) == 0


class TestJamSessionPlugin:
    def test_adds_dependency(self, session_config, middleware_user):
        plugin = SessionPlugin(
            config=session_config,
            cookie_name="session_id",
            header_name="X-Session-ID",
            user=middleware_user,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert "session" in updated_config.dependencies
        provider = updated_config.dependencies["session"]
        assert callable(provider.dependency)

    def test_adds_middleware(self, session_config, middleware_user):
        plugin = SessionPlugin(
            config=session_config,
            cookie_name="session_id",
            header_name="X-Session-ID",
            user=middleware_user,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert len(updated_config.middleware) == 1


class TestJamPASETOPlugin:
    def test_adds_dependency(self, paseto_config, middleware_user):
        plugin = PASETOPlugin(
            config=paseto_config,
            cookie_name="paseto",
            header_name="X-PASETO",
            user=middleware_user,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert "paseto" in updated_config.dependencies

    def test_adds_middleware(self, paseto_config, middleware_user):
        plugin = PASETOPlugin(
            config=paseto_config,
            cookie_name="paseto",
            header_name="X-PASETO",
            user=middleware_user,
        )
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert len(updated_config.middleware) == 1


class TestJamOAuth2Plugin:
    def test_adds_dependency(self, oauth2_config):
        plugin = OAuth2Plugin(config=oauth2_config)
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert "oauth2" in updated_config.dependencies
        provider = updated_config.dependencies["oauth2"]
        assert callable(provider.dependency)

    def test_no_middleware(self, oauth2_config):
        plugin = OAuth2Plugin(config=oauth2_config)
        app_config = AppConfig()

        updated_config = plugin.on_app_init(app_config)

        assert len(updated_config.middleware) == 0
