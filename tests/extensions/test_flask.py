# -*- coding: utf-8 -*-

import base64
import os
import pytest
from unittest.mock import MagicMock
from flask import Flask, g

pytestmark = pytest.mark.skip(
    "jam.ext is deferred until the module API rework is complete"
)

try:
    from jam.ext.flask import (
        JWTExtension,
        PASETOExtension,
        SessionExtension,
        OAuth2Extension,
    )
    from jam.jose.jwt import JWT
    from jam.paseto import create_instance as create_paseto
    from jam.sessions import create_instance as create_session
    from jam.exceptions import JamFlaskPluginConfigError
except ImportError:
    pytest.skip(
        "jam.ext is deferred until the module API rework is complete",
        allow_module_level=True,
    )


@pytest.fixture
def jwt():
    return JWT(alg="HS256", secret_key="test_secret")


@pytest.fixture
def token(jwt: JWT) -> str:
    return jwt.encode(payload={"user_id": 123})


@pytest.fixture
def session():
    path = "test_flask_sessions.json"
    if os.path.exists(path):
        os.remove(path)
    yield create_session(session_type="json", json_path=path)
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def paseto():
    key = base64.urlsafe_b64encode(b"12345678901234567890123456789012").decode()
    return create_paseto(version="v4", purpose="local", secret_key=key)


@pytest.fixture
def paseto_token(paseto) -> str:
    return paseto.encode({"user_id": 123})


class TestJWTExtension:
    @pytest.mark.parametrize("source", ["header", "cookie"])
    def test_get_payload_valid_token(self, token, source):
        app = Flask(__name__)
        if source == "header":
            JWTExtension(
                app,
                header_name="Authorization",
                alg="HS256",
                secret="test_secret",
            )
        else:
            JWTExtension(
                app,
                cookie_name="access_token",
                alg="HS256",
                secret="test_secret",
            )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            if source == "header":
                response = client.get(
                    "/", headers={"Authorization": f"Bearer {token}"}
                )
            else:
                client.set_cookie("access_token", token)
                response = client.get("/")
            assert response.get_json()["user"]["user_id"] == 123

    def test_get_payload_from_header_without_bearer_prefix(self, token):
        app = Flask(__name__)
        JWTExtension(
            app,
            header_name="X-Token",
            bearer=False,
            alg="HS256",
            secret="test_secret",
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get("/", headers={"X-Token": token})
            assert response.get_json()["user"]["user_id"] == 123

    def test_get_payload_invalid_token(self):
        app = Flask(__name__)
        JWTExtension(
            app, header_name="Authorization", alg="HS256", secret="test_secret"
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": "Bearer wrong_token"}
            )
            assert response.get_json()["user"] is None

    def test_get_payload_no_token(self):
        app = Flask(__name__)
        JWTExtension(
            app, header_name="Authorization", alg="HS256", secret="test_secret"
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get("/")
            assert response.get_json()["user"] is None


class TestSessionExtension:
    @pytest.mark.parametrize("source", ["header", "cookie"])
    def test_get_payload_valid_session(self, session, source):
        app = Flask(__name__)
        if source == "header":
            SessionExtension(
                app,
                header_name="Authorization",
                session_type="json",
                json_path="test_flask_sessions.json",
            )
        else:
            SessionExtension(
                app,
                cookie_name="sessionId",
                session_type="json",
                json_path="test_flask_sessions.json",
            )
        session_id = session.create("test", {"user_id": 123})

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            if source == "header":
                response = client.get(
                    "/", headers={"Authorization": f"Bearer {session_id}"}
                )
            else:
                client.set_cookie("sessionId", session_id)
                response = client.get("/")
            assert response.get_json()["user"]["user_id"] == 123

    def test_get_payload_invalid_session(self, session):
        app = Flask(__name__)
        SessionExtension(
            app,
            header_name="Authorization",
            session_type="json",
            json_path="test_flask_sessions.json",
        )

    def test_get_payload_no_session(self, session):
        app = Flask(__name__)
        SessionExtension(
            app,
            header_name="Authorization",
            session_type="json",
            json_path="test_flask_sessions.json",
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get("/")
            assert response.get_json()["user"] is None


class TestPASETOExtension:
    def test_get_payload_from_header(self, paseto_token):
        app = Flask(__name__)
        PASETOExtension(
            app,
            header_name="Authorization",
            version="v4",
            purpose="local",
            secret_key="MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": f"Bearer {paseto_token}"}
            )
            assert response.get_json()["user"]["user_id"] == 123

    def test_get_payload_from_cookie(self, paseto_token):
        app = Flask(__name__)
        PASETOExtension(
            app,
            cookie_name="paseto",
            version="v4",
            purpose="local",
            secret_key="MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            client.set_cookie("paseto", paseto_token)
            response = client.get("/")
            assert response.get_json()["user"]["user_id"] == 123

    def test_get_payload_no_token(self):
        app = Flask(__name__)
        PASETOExtension(
            app,
            header_name="Authorization",
            version="v4",
            purpose="local",
            secret_key="MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get("/")
            assert response.get_json()["user"] is None

    def test_get_payload_invalid_token(self):
        app = Flask(__name__)
        PASETOExtension(
            app,
            header_name="Authorization",
            version="v4",
            purpose="local",
            secret_key="MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
        )

        @app.route("/")
        def index():
            return {"user": g.payload}

        with app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": "Bearer invalid_token"}
            )
            assert response.get_json()["user"] is None


class TestOAuth2Extension:
    def test_oauth2_extension_initialization(self):
        app = Flask(__name__)
        config = {"oauth2": {"providers": {}}}
        OAuth2Extension(app, config=config)

        assert "oauth2" in app.extensions
        assert app.extensions["oauth2"] is not None


class TestBaseExtension:
    def test_raises_error_when_no_cookie_and_header_name(self):
        with pytest.raises(JamFlaskPluginConfigError) as exc_info:
            JWTExtension(Flask(__name__), cookie_name=None, header_name=None)

        assert exc_info.value.details is not None

    def test_extension_stores_auth_in_app_extensions(self):
        app = Flask(__name__)
        JWTExtension(
            app, header_name="Authorization", secret="test", alg="HS256"
        )

        assert "jwt" in app.extensions

    def test_extension_stores_auth_in_g(self):
        app = Flask(__name__)
        JWTExtension(
            app, header_name="Authorization", secret="test", alg="HS256"
        )

        @app.route("/")
        def index():
            return {"has_jwt": hasattr(g, "jwt")}

        with app.test_client() as client:
            response = client.get("/")
            assert response.get_json()["has_jwt"] is True
