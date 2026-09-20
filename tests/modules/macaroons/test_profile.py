from datetime import datetime, timezone

import pytest

from jam import Jam
from jam.aio import AsyncJam
from jam.authz import AuthorizationContext
from jam.exceptions import (
    JamConfigurationError,
    JamKeyChainError,
    JamValidationError,
)
from jam.macaroons import Caveat, Macaroon


def configured(facade=Jam):
    jam = facade(
        {
            "keychains": {
                "root": {
                    "type": "Memory",
                    "algorithm": "MACAROON-HMAC-SHA256",
                },
            },
            "macaroon": {"keychain": "root", "location": "https://issuer"},
        }
    )
    jam.keychains["root"].rotate("first")
    return jam


def test_sync_issue_attenuate_and_standalone_discharge():
    jam = configured()
    token = jam.issue(
        {"id": "alice"},
        "macaroon",
        permissions=["documents:*"],
        iss="issuer",
        aud="api",
        jti="credential-id",
        exp=300,
    )
    root = jam.macaroon.decode(token)
    assert isinstance(root, Macaroon)
    assert not token.startswith("jam:v1:")
    primary = root.add_third_party_caveat(
        b"third-party-key",
        b"approval",
        "https://approval",
    )
    discharge = Macaroon.create_discharge(
        b"third-party-key",
        b"approval",
    ).add_caveat(Caveat("permission", "documents:read"))
    with pytest.raises(JamValidationError):
        jam.authenticate(primary.encode(), "macaroon")
    with pytest.raises(JamValidationError):
        jam.authenticate(
            primary.encode(),
            "macaroon",
            discharges=[discharge],
        )
    principal = jam.authenticate(
        primary.encode(),
        "macaroon",
        discharges=[discharge.bind(primary).encode()],
    )
    assert principal.claims["iss"] == "issuer"
    assert principal.claims["aud"] == "api"
    assert principal.jti == "credential-id"
    assert jam.authorize(principal, "documents:read")
    assert not jam.authorize(principal, "documents:write")


@pytest.mark.asyncio
async def test_async_sync_interoperation_and_discharge():
    jam = configured(AsyncJam)
    token = await jam.issue(
        {"id": "alice"},
        "macaroon",
        permissions=["documents:*"],
    )
    primary = jam.macaroon.decode(token).add_third_party_caveat(
        b"approval-key",
        b"approval",
    )
    discharge = (
        Macaroon.create_discharge(
            b"approval-key",
            b"approval",
        )
        .add_caveat(Caveat("permission", "documents:read"))
        .bind(primary)
    )
    with pytest.raises(JamValidationError):
        await jam.authenticate(primary.encode(), "macaroon")
    principal = await jam.authenticate(
        primary.encode(),
        "macaroon",
        discharges=[discharge.encode()],
    )
    assert jam.authorize(principal, "documents:read")
    assert not jam.authorize(principal, "documents:write")
    sync = Jam()
    sync.macaroon = jam.macaroon
    assert (
        sync.authenticate(
            primary.encode(),
            "macaroon",
            discharges=[discharge],
        ).claims
        == principal.claims
    )


def test_rotation_retains_old_credentials_and_revocation_denies():
    jam = configured()
    old = jam.issue({"id": "alice"}, "macaroon", permissions=["read"])
    jam.keychains["root"].rotate("second")
    new = jam.issue({"id": "alice"}, "macaroon", permissions=["read"])
    assert jam.authenticate(old, "macaroon").subject["id"] == "alice"
    jam.keychains["root"].revoke("first")
    with pytest.raises(JamKeyChainError):
        jam.authenticate(old, "macaroon")
    assert jam.authenticate(new, "macaroon").subject["id"] == "alice"


@pytest.mark.parametrize(
    "caveat",
    [
        Caveat("permission", "write"),
        Caveat(
            "condition",
            {
                "field": "context.resource.owner",
                "operator": "eq",
                "value": "@subject.id",
            },
        ),
        Caveat("expires_at", "2000-01-01T00:00:00Z"),
        Caveat("not_before", "2100-01-01T00:00:00Z"),
    ],
)
@pytest.mark.parametrize("facade", [Jam, AsyncJam])
def test_all_builtin_restrictions_fail_closed_before_custom_policy(
    facade,
    caveat,
):
    jam = configured(facade)
    token = jam.macaroon.issue(
        {"sub": "alice", "permissions": ["read"]},
    )
    restricted = jam.macaroon.decode(token).add_caveat(caveat)
    claims, constraints = jam.macaroon.authenticate(restricted.encode())
    from jam.authz import Principal

    principal = Principal({"id": "alice"}, claims, "macaroon", constraints)

    class AllowAll:
        def check(self, *args):
            pytest.fail("policy must not run before mandatory restrictions")

    jam._policy = AllowAll()
    assert not jam.authorize(
        principal,
        "read",
        AuthorizationContext(now=datetime(2026, 1, 1, tzinfo=timezone.utc)),
    )


def test_unknown_caveats_fail_closed():
    jam = configured()
    token = jam.issue({"id": "alice"}, "macaroon", permissions=["read"])
    restricted = jam.macaroon.decode(token).add_caveat(
        Caveat("unregistered", True),
    )
    with pytest.raises(JamValidationError):
        jam.authenticate(restricted.encode(), "macaroon")


@pytest.mark.parametrize(
    "config",
    [None, [], {}, {"keychain": "missing"}, {"keychain": 42}],
)
def test_invalid_module_config_is_rejected(config):
    with pytest.raises(JamConfigurationError):
        Jam({"macaroon": config})


def test_wrong_keychain_algorithm_is_rejected():
    with pytest.raises(JamConfigurationError):
        Jam(
            {
                "keychains": {"root": {"type": "Memory", "algorithm": "HS256"}},
                "macaroon": {"keychain": "root"},
            }
        )
