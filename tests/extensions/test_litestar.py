# -*- coding: utf-8 -*-

from unittest.mock import MagicMock

import pytest
from litestar import Litestar, Request, get
from litestar.config.app import AppConfig
from litestar.exceptions import (
    NotAuthorizedException,
    PermissionDeniedException,
)
from litestar.testing import TestClient

from jam.authz import Principal
from jam.ext import CredentialSource
from jam.ext.litestar import JamPlugin, permission_guard


def test_plugin_adds_jam_dependency_and_instance_scoped_middleware():
    jam = MagicMock()
    plugin = JamPlugin(
        jam,
        sources=[CredentialSource.cookie("session")],
        via="session",
    )

    config = plugin.on_app_init(AppConfig())

    assert "jam" in config.dependencies
    assert len(config.middleware) == 1


def test_plugin_can_only_install_dependency():
    config = JamPlugin(MagicMock(), middleware=False).on_app_init(AppConfig())

    assert "jam" in config.dependencies
    assert config.middleware == []


def test_plugin_authenticates_real_litestar_request():
    jam = MagicMock()
    jam.authenticate.return_value = Principal({"id": "42"}, {}, "jwt")

    @get("/", sync_to_thread=False)
    def index(request: Request) -> dict:
        return {"id": request.user.subject["id"]}

    app = Litestar([index], plugins=[JamPlugin(jam)])
    with TestClient(app) as client:
        response = client.get(
            "/",
            headers={"Authorization": "Bearer token"},
        )

    assert response.status_code == 200
    assert response.json() == {"id": "42"}


def test_permission_guard_distinguishes_unauthenticated_and_forbidden():
    jam = MagicMock()
    guard = permission_guard(jam, "post:edit")
    connection = MagicMock()
    connection.user = None

    with pytest.raises(NotAuthorizedException):
        guard(connection, MagicMock())

    connection.user = Principal({"id": "42"}, {}, "jwt")
    jam.authorize.return_value = False
    with pytest.raises(PermissionDeniedException):
        guard(connection, MagicMock())

    jam.authorize.return_value = True
    guard(connection, MagicMock())
