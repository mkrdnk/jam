# -*- coding: utf-8 -*-

from unittest.mock import MagicMock

from flask import Flask

from jam.authz import Principal
from jam.ext import CredentialSource
from jam.ext.flask import JamAuth, current_principal, get_jam


def test_flask_extension_supports_app_factory_and_current_principal():
    jam = MagicMock()
    jam.authenticate.return_value = Principal({"id": "42"}, {}, "jwt")
    auth = JamAuth(jam=jam)
    app = Flask(__name__)
    auth.init_app(app)

    @app.get("/")
    @auth.login_required
    def index():
        return {
            "id": current_principal.subject["id"],
            "same_jam": get_jam() is jam,
        }

    response = app.test_client().get(
        "/",
        headers={"Authorization": "Bearer token"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"id": "42", "same_jam": True}
    jam.authenticate.assert_called_once_with("token", via=None)


def test_login_required_returns_401():
    auth = JamAuth(jam=MagicMock())
    app = Flask(__name__)
    auth.init_app(app)

    @app.get("/")
    @auth.login_required
    def index():
        return "ok"

    response = app.test_client().get("/")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_permission_required_returns_403_or_calls_view():
    jam = MagicMock()
    jam.authenticate.return_value = Principal({"id": "42"}, {}, "jwt")
    auth = JamAuth(
        jam=jam,
        sources=[CredentialSource.cookie("access_token")],
    )
    app = Flask(__name__)
    auth.init_app(app)

    @app.get("/")
    @auth.permission_required("post:edit")
    def index():
        return "ok"

    client = app.test_client()
    client.set_cookie("access_token", "token")
    jam.authorize.return_value = False
    assert client.get("/").status_code == 403

    jam.authorize.return_value = True
    assert client.get("/").data == b"ok"
    jam.authorize.assert_called_with(
        jam.authenticate.return_value,
        "post:edit",
        None,
    )
