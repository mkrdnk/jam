"""Trust-boundary, attenuation, and dynamic constraint regression tests."""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

import pytest

from jam import AuthorizationContext, BaseSubject, Jam
from jam.authz import ConditionConstraint
from jam.exceptions import InvalidCaveatError, JamKeyChainError
from jam.keychain import FileStorage
from jam.macaroons import (
    Caveat,
    CaveatRegistry,
    FirstPartyCaveat,
    Limits,
    Macaroon,
    MacaroonModule,
    SerializationError,
    VerificationError,
    Verifier,
)


@dataclass
class User(BaseSubject):
    id: str


@pytest.fixture
def jam():
    instance = Jam(
        {
            "keychains": {"root": {"type": "Memory"}},
            "macaroon": {"keychain": "root"},
        },
        subject=User,
    )
    instance.keychains["root"].rotate("first")
    return instance


def test_acceptance_flow_and_permission_intersection(jam):
    original = jam.issue(User("42"), "macaroon", permissions=["documents:*"])
    delegated = (
        jam.macaroon.decode(original)
        .add_caveat(Caveat("permission", "documents:read"))
        .add_caveat(Caveat("permission", "*"))
        .add_caveat(
            Caveat(
                "condition",
                {
                    "field": "context.resource.owner_id",
                    "operator": "eq",
                    "value": "@subject.id",
                },
            )
        )
    )
    principal = jam.authenticate(delegated.encode(), "macaroon")
    owned = AuthorizationContext(resource={"owner_id": "42"})
    assert jam.authorize(principal, "documents:read", owned)
    assert not jam.authorize(principal, "documents:write", owned)
    assert not jam.authorize(
        principal,
        "documents:read",
        AuthorizationContext(resource={"owner_id": "another"}),
    )
    assert not jam.authorize(principal, "documents:read")
    assert jam.authorize(
        jam.authenticate(original, "macaroon"), "documents:write"
    )


@pytest.mark.parametrize(
    "name,operator",
    [
        ("expires_at", "lt"),
        ("not_before", "gte"),
    ],
)
def test_time_boundaries_are_authorization_not_authentication(
    jam, name, operator
):
    boundary = datetime(2020, 1, 1, tzinfo=timezone.utc)
    token = jam.macaroon.decode(
        jam.issue(User("42"), "macaroon", permissions=["read"])
    ).add_caveat(Caveat(name, boundary.isoformat()))
    principal = jam.authenticate(token.encode(), "macaroon")
    before = AuthorizationContext(now=boundary - timedelta(microseconds=1))
    at = AuthorizationContext(now=boundary)
    assert jam.authorize(principal, "read", before) is (operator == "lt")
    assert jam.authorize(principal, "read", at) is (operator == "gte")


def test_relative_issue_time_is_only_stored_in_caveats(jam):
    before = datetime.now(timezone.utc)
    token = jam.issue(
        User("42"), "macaroon", permissions=["read"], exp=60, nbf=-60
    )
    principal = jam.authenticate(token, "macaroon")
    assert "exp" not in principal.claims and "nbf" not in principal.claims
    assert len(principal.constraints) == 2
    assert jam.authorize(principal, "read")
    assert not jam.authorize(
        principal,
        "read",
        AuthorizationContext(now=before + timedelta(seconds=61)),
    )


@pytest.mark.parametrize(
    "caveat",
    [
        Caveat("expires_at", "2026-01-01T00:00:00"),
        Caveat("expires_at", 123),
        Caveat("not_before", "not-a-time"),
        Caveat("condition", {"all": []}),
        Caveat("condition", {"any": []}),
        Caveat("condition", {"not": {}}),
        Caveat("condition", {"field": "subject.id", "operator": "unsupported"}),
        Caveat("permission", 1),
        Caveat("unknown", "value"),
        b"jam:v2:unsupported",
    ],
)
def test_malformed_caveats_fail_during_authentication(jam, caveat):
    token = jam.macaroon.decode(jam.issue(User("42"), "macaroon"))
    with pytest.raises(InvalidCaveatError):
        jam.authenticate(token.add_caveat(caveat).encode(), "macaroon")


def test_unknown_jam_version_cannot_be_accepted_by_raw_satisfier():
    token = Macaroon.create("key", "id").add_caveat(b"jam:v2:opaque")
    with pytest.raises(InvalidCaveatError):
        Verifier().satisfy_general(lambda _: True).verify(token, "key")


def test_structured_caveat_rejects_noncanonical_inner_base64():
    raw = Caveat("x", 1).encode()
    with pytest.raises(SerializationError):
        Caveat.decode(raw + b"==")


def test_satisfier_errors_become_verification_errors():
    token = Macaroon.create("key", "id").add_caveat(b"bad")

    def broken(value):
        raise RuntimeError("callback failed")

    with pytest.raises(VerificationError):
        Verifier().satisfy_general(broken).verify(token, "key")


def test_runtime_dunder_is_not_executed(jam):
    class Unsafe:
        def __bool__(self):
            pytest.fail("An untrusted caveat must not invoke __bool__")

    token = jam.macaroon.decode(
        jam.issue(User("42"), "macaroon", permissions=["read"])
    ).add_caveat(
        Caveat(
            "condition",
            {
                "field": "context.resource.value",
                "operator": "truthy",
            },
        )
    )
    principal = jam.authenticate(token.encode(), "macaroon")
    assert not jam.authorize(
        principal, "read", AuthorizationContext(resource={"value": Unsafe()})
    )


def test_custom_registry_and_opaque_verifier(jam):
    registry = CaveatRegistry()
    registry.register(
        "tenant",
        lambda value: ConditionConstraint(
            "context.attributes.tenant",
            value=value,
        ),
    )
    jam.macaroon.registry = registry
    token = (
        jam.macaroon.decode(
            jam.issue(User("42"), "macaroon", permissions=["read"])
        )
        .add_caveat(Caveat("tenant", "one"))
        .add_caveat(b"approved")
    )
    with pytest.raises(VerificationError):
        jam.authenticate(token.encode(), "macaroon")
    jam.macaroon.satisfy_exact(b"approved")
    principal = jam.authenticate(token.encode(), "macaroon")
    assert jam.authorize(
        principal, "read", AuthorizationContext(attributes={"tenant": "one"})
    )
    assert not jam.authorize(
        principal, "read", AuthorizationContext(attributes={"tenant": "two"})
    )


def test_attenuation_cannot_remove_replace_or_modify_root():
    original = Macaroon.create("secret", "root-authority")
    delegated = original.add_caveat(b"read").add_caveat(b"tenant")
    verifier = Verifier().satisfy_general(lambda _: True)
    for forged in (
        replace(delegated, caveats=delegated.caveats[:-1]),
        replace(delegated, caveats=(FirstPartyCaveat(b"write"),)),
        replace(delegated, identifier=b"wider-root-authority"),
    ):
        with pytest.raises(VerificationError):
            verifier.verify(forged, "secret")
    with pytest.raises(VerificationError):
        verifier.verify(original, "wrong-key")
    assert original.signature != delegated.signature
    verifier.verify(original, "secret")
    verifier.verify(delegated, "secret")


def test_nested_discharge_caveats_count_towards_total_limit():
    primary = Macaroon.create("key", "id").add_third_party_caveat("other", "d")
    discharge = (
        Macaroon.create_discharge("other", "d").add_caveat(b"ok").bind(primary)
    )
    with pytest.raises(VerificationError):
        Verifier(Limits(caveat_count=1)).satisfy_exact(b"ok").verify(
            primary, "key", [discharge]
        )


def test_file_keychain_rotation_survives_reopening(tmp_path):
    path = tmp_path / "keys"
    chain = FileStorage(path, "MACAROON-HMAC-SHA256")
    chain.rotate("first")
    module = MacaroonModule(chain)
    token = module.issue({"sub": "42", "permissions": ["read"]})
    chain.rotate("second")
    reopened = MacaroonModule(FileStorage(path, "MACAROON-HMAC-SHA256"))
    assert reopened.authenticate(token)[0]["sub"] == "42"
    reopened.keychain.revoke("first")
    with pytest.raises(JamKeyChainError):
        reopened.authenticate(token)
