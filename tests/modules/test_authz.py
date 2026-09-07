# -*- coding: utf-8 -*-

from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from jam import (
    AuthorizationContext,
    BaseSubject,
    Jam,
    Policy,
    Principal,
)
from jam.exceptions import JamConfigurationError


@dataclass
class User(BaseSubject):
    """Subject used by authorization tests."""

    id: str
    role: str = "user"
    active: bool = True
    protected: bool = False
    deleted_at: str | None = None


@pytest.fixture
def user():
    """Return an active administrator."""
    return User(id="42", role="admin")


def test_compact_rules_remain_supported(user):
    """Compact predicates use OR semantics and parse scalar values."""
    policy = Policy(
        {
            "post:edit": ["role=editor", "id='42'"],
            "account:use": ["active=true"],
        }
    )

    assert policy.check(user, "post:edit")
    assert policy.check(user, "account:use")
    assert not policy.check(user, "post:delete")


def test_compact_rules_only_access_subject_data(user):
    """Missing, method and private attributes must not grant access."""
    policy = Policy(
        {
            "missing": ["missing=None"],
            "method": ["to_dict"],
        }
    )

    assert not policy.check(user, "missing")
    assert not policy.check(user, "method")
    with pytest.raises(JamConfigurationError, match="Invalid subject field"):
        Policy({"private": ["__class__"]})


def test_strict_rule_does_not_invoke_methods(user):
    """Structured rules must not evaluate callable attributes."""
    policy = Policy(
        [
            {
                "permissions": ["account:use"],
                "when": {
                    "field": "subject.to_dict",
                    "operator": "truthy",
                },
            }
        ]
    )

    assert not policy.check(user, "account:use")


def test_token_permission_grants_access_without_policy_rules(user):
    """A permission embedded into one credential acts as a grant."""
    principal = Principal(
        subject=user,
        claims={"permissions": ["user:read", "user:delete"]},
        token_type="jwt",
    )
    policy = Policy()

    assert policy.check(principal, "user:delete")
    assert not policy.check(principal, "user:update")


def test_permission_wildcards_are_namespace_scoped(user):
    """Namespace and global permission wildcards are supported."""
    principal = Principal(
        subject=user,
        claims={"permissions": ["user:*"]},
        token_type="jwt",
    )

    assert principal.has_permission("user:delete")
    assert not principal.has_permission("admin:delete")
    assert Policy({"user:*": ["role=admin"]}).check(user, "user:delete")


def test_declared_token_grants_limit_policy_rules(user):
    """A policy cannot add a permission excluded from credential grants."""
    principal = Principal(
        subject=user,
        claims={"permissions": ["user:read"]},
        token_type="jwt",
    )
    policy = Policy({"user:delete": ["role=admin"]})

    assert not policy.check(principal, "user:delete")


def test_deny_rule_takes_precedence(user):
    """A matching deny rule overrides a matching allow rule."""
    policy = Policy(
        [
            {
                "effect": "allow",
                "permissions": ["user:*"],
                "when": {
                    "field": "subject.role",
                    "operator": "eq",
                    "value": "admin",
                },
            },
            {
                "effect": "deny",
                "permissions": ["user:delete"],
                "when": {
                    "field": "context.resource.protected",
                    "operator": "eq",
                    "value": True,
                },
            },
        ]
    )
    protected = User(id="protected", protected=True)

    assert not policy.check(
        user,
        "user:delete",
        AuthorizationContext(resource=protected),
    )


def test_logical_conditions_and_data_roots(user):
    """Rules compose conditions across subject, token and request data."""
    principal = Principal(
        subject=user,
        claims={
            "permissions": ["user:delete"],
            "groups": ["operators", "admins"],
        },
        token_type="jwt",
    )
    policy = Policy(
        [
            {
                "permissions": ["user:delete"],
                "when": {
                    "all": [
                        {
                            "field": "token.groups",
                            "operator": "contains_all",
                            "value": ["operators", "admins"],
                        },
                        {
                            "not": {
                                "field": "context.request.ip",
                                "operator": "ip_in_network",
                                "value": "198.51.100.0/24",
                            }
                        },
                        {
                            "any": [
                                {
                                    "field": "subject.role",
                                    "operator": "matches",
                                    "value": "admin|owner",
                                },
                                {
                                    "field": "subject.id",
                                    "operator": "eq",
                                    "value": "root",
                                },
                            ]
                        },
                    ]
                },
            }
        ]
    )

    assert policy.check(
        principal,
        "user:delete",
        AuthorizationContext(request={"ip": "192.0.2.10"}),
    )
    assert not policy.check(
        principal,
        "user:delete",
        AuthorizationContext(request={"ip": "198.51.100.10"}),
    )


def test_invalid_runtime_context_fails_closed(user):
    """Malformed request values deny access instead of raising an error."""
    policy = Policy(
        [
            {
                "permissions": ["network:use"],
                "when": {
                    "field": "context.request.ip",
                    "operator": "ip_in_network",
                    "value": "192.0.2.0/24",
                },
            }
        ]
    )

    assert not policy.check(
        user,
        "network:use",
        AuthorizationContext(request={"ip": "not-an-ip"}),
    )


@pytest.mark.parametrize(
    ("hour", "expected"),
    [(16, False), (17, True), (18, False)],
)
def test_time_condition(user, hour, expected):
    """Time windows use an injected clock and an explicit timezone."""
    policy = Policy(
        [
            {
                "effect": "allow",
                "permissions": ["user:delete"],
                "when": {
                    "all": [
                        {
                            "field": "subject.active",
                            "operator": "eq",
                            "value": True,
                        },
                        {
                            "field": "context.time",
                            "operator": "between",
                            "value": ["17:00", "18:00"],
                            "timezone": "UTC",
                        },
                    ]
                },
            }
        ]
    )
    context = AuthorizationContext(
        now=datetime(2026, 1, 1, hour, tzinfo=timezone.utc)
    )

    assert policy.check(user, "user:delete", context) is expected


def test_invalid_rules_fail_during_initialization():
    """Malformed policies fail before handling an authorization request."""
    with pytest.raises(
        JamConfigurationError,
        match="Predicates must be a list",
    ):
        Policy({"user:delete": "role=admin"})

    with pytest.raises(
        JamConfigurationError,
        match="Invalid authorization field",
    ):
        Policy(
            [
                {
                    "permissions": ["user:delete"],
                    "when": {
                        "field": "subject.__class__",
                        "operator": "truthy",
                    },
                }
            ]
        )

    with pytest.raises(
        JamConfigurationError,
        match="Unknown authorization operator",
    ):
        Policy(
            [
                {
                    "permissions": ["user:delete"],
                    "when": {
                        "field": "subject.active",
                        "operator": "execute_python",
                    },
                }
            ]
        )


def test_jam_round_trip_preserves_credential_permissions():
    """Jam returns token claims alongside the reconstructed subject."""
    jam = Jam(
        config={
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "SECRET",
                }
            }
        },
        subject=User,
    )

    token = jam.issue(
        User(id="42", role="admin"),
        permissions=["user:delete"],
    )
    principal = jam.authenticate(token)

    assert principal.subject.id == "42"
    assert principal.permissions == {"user:delete"}
    assert principal.jti
    assert jam.authorize(principal, "user:delete")
    assert not jam.authorize(principal, "user:update")


def test_paseto_does_not_get_an_implicit_jwt_id():
    """Non-JWT credentials do not receive the JWT-specific jti claim."""
    jam = Jam(
        config={
            "paseto": {
                "version": "v4",
                "purpose": "local",
                "secret_key": b"x" * 32,
            }
        }
    )

    token = jam.issue(
        {"id": "42"},
        via="paseto",
        permissions=["user:delete"],
    )
    principal = jam.authenticate(token)

    assert "jti" not in principal.claims
    assert principal.permissions == {"user:delete"}


@dataclass
class Document(BaseSubject):
    """Dataclass resource with an ownership field."""

    id: str
    author_id: str


class PlainResource:
    """Non-dataclass resource accessed through public attributes."""

    def __init__(self, author_id: str) -> None:
        """Initialize a plain resource owner."""
        self.author_id = author_id
        self.locked: bool = False

    def is_public(self) -> bool:
        """Methods must stay hidden from rule evaluation."""
        return True


def test_value_reference_compares_subject_and_resource_fields():
    """An @-prefixed value resolves a field path against context roots."""
    policy = Policy(
        [
            {
                "effect": "allow",
                "permissions": ["document:delete"],
                "when": {
                    "field": "subject.id",
                    "operator": "eq",
                    "value": "@context.resource.author_id",
                },
            }
        ]
    )
    owner = User(id="42")
    document = Document(id="doc-1", author_id="42")

    assert policy.check(
        owner, "document:delete", AuthorizationContext(resource=document)
    )

    stranger = User(id="43")
    assert not policy.check(
        stranger, "document:delete", AuthorizationContext(resource=document)
    )


def test_value_reference_missing_field_raises():
    """A reference to a missing field is a configuration error."""
    policy = Policy(
        [
            {
                "permissions": ["document:delete"],
                "when": {
                    "field": "subject.id",
                    "operator": "eq",
                    "value": "@context.resource.author_id",
                },
            }
        ]
    )
    resource = User(id="42")

    with pytest.raises(
        JamConfigurationError,
        match="value reference has no value",
    ):
        policy.check(
            user, "document:delete", AuthorizationContext(resource=resource)
        )


def test_value_reference_invalid_path_fails_initialization():
    """A reference path without a data root is rejected at build time."""
    with pytest.raises(
        JamConfigurationError,
        match="Invalid authorization value reference",
    ):
        Policy(
            [
                {
                    "permissions": ["document:delete"],
                    "when": {
                        "field": "subject.id",
                        "operator": "eq",
                        "value": "@resource.author_id",
                    },
                }
            ]
        )


def test_value_reference_supports_plain_class_resource(user):
    """Non-dataclass resource objects resolve through public attributes."""
    policy = Policy(
        [
            {
                "permissions": ["document:delete"],
                "when": {
                    "field": "subject.id",
                    "operator": "eq",
                    "value": "@context.resource.author_id",
                },
            }
        ]
    )
    resource = PlainResource(author_id="42")

    assert policy.check(
        user, "document:delete", AuthorizationContext(resource=resource)
    )
    assert not policy.check(
        User(id="7"), "document:delete", AuthorizationContext(resource=resource)
    )


def test_plain_resource_methods_are_not_evaluated():
    """Callable attributes on plain resources must not grant access."""
    policy = Policy(
        [
            {
                "permissions": ["document:read"],
                "when": {
                    "field": "context.resource.is_public",
                    "operator": "eq",
                    "value": True,
                },
            }
        ]
    )
    resource = PlainResource(author_id="42")

    assert not policy.check(
        user, "document:read", AuthorizationContext(resource=resource)
    )


def test_value_reference_supports_nested_plain_class_resource():
    """Nested plain objects resolve through public attribute chains."""
    resource = PlainResource(author_id="42")
    resource.owner = SimpleNamespace(id="7")
    policy = Policy(
        [
            {
                "permissions": ["document:delete"],
                "when": {
                    "field": "subject.id",
                    "operator": "eq",
                    "value": "@context.resource.owner.id",
                },
            }
        ]
    )

    assert policy.check(
        User(id="7"), "document:delete", AuthorizationContext(resource=resource)
    )
    assert not policy.check(
        user, "document:delete", AuthorizationContext(resource=resource)
    )


def test_value_reference_supports_token_and_subject_roots():
    """References resolve against the same roots available to fields."""
    principal = Principal(
        subject=User(id="42"),
        claims={"permissions": ["account:use"], "tenant": "42"},
        token_type="jwt",
    )
    policy = Policy(
        [
            {
                "permissions": ["account:use"],
                "when": {
                    "field": "token.tenant",
                    "operator": "eq",
                    "value": "@subject.id",
                },
            }
        ]
    )

    assert policy.check(principal, "account:use")
