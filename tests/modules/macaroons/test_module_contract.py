from typing import get_args

import pytest

from jam import Jam
from jam.__core__ import JamAuthType, JamIssueType
from jam.aio import AsyncJam
from jam.authz import Principal
from jam.exceptions import JamConfigurationError, JamValidationError
from jam.macaroons import CaveatRegistry


class AllowAll:
    def __init__(self):
        self.calls = 0

    def check(self, principal, permission, context=None):
        self.calls += 1
        return True


class Restriction:
    def __init__(self, result):
        self.result = result

    def check(self, principal, permission, context):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.mark.parametrize("facade", [Jam, AsyncJam])
@pytest.mark.parametrize("token_type", ["jwt", "macaroon"])
def test_constraints_precede_custom_policy(facade, token_type):
    jam = facade()
    policy = AllowAll()
    jam._policy = policy
    principal = Principal(
        {"id": "alice"},
        {"permissions": ["read"]},
        token_type,
        (Restriction(False),),
    )
    assert not jam.authorize(principal, "read")
    assert policy.calls == 0
    principal.constraints = (Restriction(JamValidationError()),)
    assert not jam.authorize(principal, "read")
    assert policy.calls == 0
    principal.constraints = (Restriction(RuntimeError("bug")),)
    with pytest.raises(RuntimeError, match="bug"):
        jam.authorize(principal, "read")


@pytest.mark.parametrize("facade", [Jam, AsyncJam])
def test_custom_policy_cannot_widen_root_grant(facade):
    jam = facade()
    jam._policy = policy = AllowAll()
    principal = Principal(
        {"id": "alice"},
        {"permissions": ["read"]},
        "macaroon",
    )
    assert not jam.authorize(principal, "write")
    assert policy.calls == 0
    assert jam.authorize(principal, "read")
    assert policy.calls == 1


@pytest.mark.parametrize("facade", [Jam, AsyncJam])
def test_constraints_cannot_grant_permission(facade):
    jam = facade()
    principal = Principal(
        {"id": "alice"},
        {},
        "jwt",
        (Restriction(True),),
    )
    assert not jam.authorize(principal, "read")


@pytest.mark.parametrize("facade", [Jam, AsyncJam])
def test_registry_is_instance_owned(facade):
    config = {
        "keychains": {"root": {"type": "Memory"}},
        "macaroon": {"keychain": "root"},
    }
    first, second = facade(config), facade(config)
    assert first.macaroon.registry is not second.macaroon.registry
    registry = CaveatRegistry()
    assert (
        facade(config, caveat_registry=registry).macaroon.registry is registry
    )


@pytest.mark.parametrize("facade", [Jam, AsyncJam])
def test_core_delegates_config_without_interpreting_it(monkeypatch, facade):
    sentinel = object()
    module = object()
    registry = CaveatRegistry()
    calls = []

    def factory(config, *, resolve_keychain, registry):
        calls.append((config, resolve_keychain, registry))
        return module

    monkeypatch.setattr("jam.macaroons.create_instance", factory)
    jam = facade({"macaroon": sentinel}, caveat_registry=registry)
    assert jam.macaroon is module
    assert calls[0][0] is sentinel
    assert callable(calls[0][1])
    assert calls[0][2] is registry


def test_closed_credential_types():
    assert set(get_args(JamIssueType)) == {
        "jwt",
        "paseto",
        "session",
        "macaroon",
        "saml",
    }
    assert set(get_args(JamAuthType)) == {
        "jwt",
        "jwe",
        "paseto",
        "session",
        "macaroon",
        "saml",
    }


def test_missing_sync_module():
    jam = Jam()
    with pytest.raises(JamConfigurationError):
        jam.issue({"id": "alice"}, "macaroon")
    with pytest.raises(JamConfigurationError):
        jam.authenticate("invalid", "macaroon")


@pytest.mark.asyncio
async def test_missing_async_module():
    jam = AsyncJam()
    with pytest.raises(JamConfigurationError):
        await jam.issue({"id": "alice"}, "macaroon")
    with pytest.raises(JamConfigurationError):
        await jam.authenticate("invalid", "macaroon")
