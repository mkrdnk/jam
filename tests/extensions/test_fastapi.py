# -*- coding: utf-8 -*-

from unittest.mock import MagicMock

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from jam.authz import Principal
from jam.ext.fastapi import JamAuth


def make_app(jam):
    auth = JamAuth(jam)
    app = FastAPI()

    @app.get("/required")
    def required(principal=Depends(auth)):
        return {"id": principal.subject["id"]}

    @app.get("/optional")
    def optional(principal=Depends(auth.optional)):
        return {"authenticated": principal is not None}

    @app.get("/protected")
    def protected(principal=Depends(auth.require("post:edit"))):
        return {"id": principal.subject["id"]}

    return app


def test_required_and_optional_dependencies():
    jam = MagicMock()
    jam.authenticate.return_value = Principal({"id": "42"}, {}, "jwt")
    client = TestClient(make_app(jam))

    assert client.get("/required").status_code == 401
    assert client.get("/optional").json() == {"authenticated": False}
    response = client.get(
        "/required",
        headers={"Authorization": "Bearer token"},
    )
    assert response.json() == {"id": "42"}


def test_permission_dependency():
    jam = MagicMock()
    jam.authenticate.return_value = Principal({"id": "42"}, {}, "jwt")
    client = TestClient(make_app(jam))
    headers = {"Authorization": "Bearer token"}

    jam.authorize.return_value = False
    assert client.get("/protected", headers=headers).status_code == 403

    jam.authorize.return_value = True
    assert client.get("/protected", headers=headers).status_code == 200


def test_bearer_security_is_in_openapi():
    schema = make_app(MagicMock()).openapi()

    security = schema["paths"]["/required"]["get"]["security"]
    assert security == [{"HTTPBearer": []}]
