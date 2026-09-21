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
    ("name", "boundary"),
    [
        ("expires_at", datetime(2020, 1, 1, tzinfo=timezone.utc)),
        ("not_before", datetime(2100, 1, 1, tzinfo=timezone.utc)),
    ],
)
def test_invalid_time_boundaries_fail_authentication(jam, name, boundary):
    token = jam.macaroon.decode(
        jam.issue(User("42"), "macaroon", permissions=["read"])
    ).add_caveat(Caveat(name, boundary.isoformat()))
    with pytest.raises(VerificationError):
        jam.authenticate(token.encode(), "macaroon")


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
    module = MacaroonModule()
    module.satisfy_general(lambda _: True)
    with pytest.raises(InvalidCaveatError):
        module.verify(token.encode(), "key")


def test_structured_caveat_rejects_noncanonical_inner_base64():
    raw = Caveat("x", 1).encode()
    with pytest.raises(SerializationError):
        Caveat.decode(raw + b"==")


def test_invalid_claim_unicode_is_a_serialization_error(jam):
    with pytest.raises(SerializationError):
        jam.macaroon.issue({"bad": "\ud800"})


def test_satisfier_errors_become_verification_errors():
    token = Macaroon.create("key", "id").add_caveat(b"bad")

    def broken(value):
        raise RuntimeError("callback failed")

    module = MacaroonModule()
    module.satisfy_general(broken)
    with pytest.raises(VerificationError):
        module.verify(token.encode(), "key")


def test_structured_satisfiers_receive_immutable_values():
    token = Macaroon.create("key", "id").add_caveat(
        Caveat("custom", {"nested": [1, 2]})
    )
    received = []

    def check(value):
        received.append(value)
        with pytest.raises(TypeError):
            value["changed"] = True
        with pytest.raises(AttributeError):
            value["nested"].append(3)
        return True

    result = MacaroonModule().verify(
        token.encode(),
        "key",
        structured_satisfiers={"custom": check},
    )
    assert result.caveats[0].value is received[0]
    with pytest.raises(TypeError):
        result.caveats[0].value["changed"] = True


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
    verifier = MacaroonModule()
    verifier.satisfy_general(lambda _: True)
    for forged in (
        replace(delegated, caveats=delegated.caveats[:-1]),
        replace(delegated, caveats=(FirstPartyCaveat(b"write"),)),
        replace(delegated, identifier=b"wider-root-authority"),
    ):
        with pytest.raises(VerificationError):
            verifier.verify(forged.encode(), "secret")
    with pytest.raises(VerificationError):
        verifier.verify(original.encode(), "wrong-key")
    assert original.signature != delegated.signature
    verifier.verify(original.encode(), "secret")
    verifier.verify(delegated.encode(), "secret")


def test_nested_discharge_caveats_count_towards_total_limit():
    primary = Macaroon.create("key", "id").add_third_party_caveat("other", "d")
    discharge = (
        Macaroon.create_discharge("other", "d").add_caveat(b"ok").bind(primary)
    )
    module = MacaroonModule(limits=Limits(caveat_count=1))
    module.satisfy_exact(b"ok")
    with pytest.raises(VerificationError):
        module.verify(
            primary.encode(), "key", [discharge.encode()]
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
