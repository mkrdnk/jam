"""Regression coverage for credential constraints and policy compatibility."""

from dataclasses import FrozenInstanceError, dataclass
from datetime import datetime, timezone

import pytest

from jam.authz import (
    AuthorizationContext,
    ConditionConstraint,
    PermissionConstraint,
    Policy,
    Principal,
)
from jam.exceptions import JamConfigurationError


def check(operator="eq", value=None, actual=None, **kwargs):
    constraint = ConditionConstraint(
        "context.resource.value", operator, value, **kwargs
    )
    return constraint.check(
        Principal({}, {}, "test"),
        "documents:read",
        AuthorizationContext(resource={"value": actual}),
    )


@pytest.mark.parametrize(
    ("operator", "actual", "value"),
    [
        ("eq", ["a"], ["a"]),
        ("ne", "a", "b"),
        ("exists", None, True),
        ("truthy", "a", None),
        ("in", "a", ["a", "b"]),
        ("not_in", "c", ["a", "b"]),
        ("contains", ["a", "b"], "a"),
        ("contains_any", ["a"], ["a", "b"]),
        ("contains_all", ["a", "b"], ["a", "b"]),
        ("starts_with", "abc", "a"),
        ("ends_with", "abc", "c"),
        ("matches", "admin", "admin|owner"),
        ("matches", "docs:read", r"docs:\w+"),
        ("ip_in_network", "10.0.0.1", "10.0.0.0/8"),
        ("between", 5, [1, 10]),
        ("gt", 2, 1),
        ("gte", 2, 2),
        ("lt", 1, 2),
        ("lte", 2, 2),
    ],
)
def test_all_comparison_operators(operator, actual, value):
    assert check(operator, value, actual)


def test_timezone_and_overnight_window():
    now = datetime(2025, 1, 1, 22, 30, tzinfo=timezone.utc)
    assert check("between", ["00:00", "02:00"], now, timezone="Europe/Moscow")
    assert check("between", ["22:00", "02:00"], now)
    assert not check("between", ["00:00", "01:00"], now)


@pytest.mark.parametrize("operator", ["eq", "ne", "exists", "not_in"])
def test_missing_actual_always_denies_even_exists_false(operator):
    restriction = ConditionConstraint("subject.missing", operator, False)
    assert not restriction.check(
        Principal({}, {}, "test"), "read", AuthorizationContext()
    )


def test_missing_reference_denies_but_server_policy_still_raises():
    condition = {"field": "subject.id", "value": "@context.resource.owner"}
    principal = Principal({"id": 1}, {}, "test")
    assert not ConditionConstraint(**condition).check(
        principal, "read", AuthorizationContext()
    )
    policy = Policy([{"permissions": ["read"], "when": condition}])
    with pytest.raises(JamConfigurationError):
        policy.check(principal, "read")


def test_server_policy_exists_false_still_matches_missing_field():
    policy = Policy(
        [
            {
                "permissions": ["read"],
                "when": {
                    "field": "subject.missing",
                    "operator": "exists",
                    "value": False,
                },
            }
        ]
    )
    assert policy.check({}, "read")


def test_snapshot_preserves_nested_list_and_mapping_comparisons():
    original = {"nested": [{"roles": ["reader"]}]}
    restriction = ConditionConstraint("subject.data", value=original)
    original["nested"][0]["roles"].append("admin")
    principal = Principal(
        {"data": {"nested": [{"roles": ["reader"]}]}}, {}, "test"
    )
    assert restriction.check(principal, "read", AuthorizationContext())
    with pytest.raises(TypeError):
        restriction.value["other"] = True
    with pytest.raises(FrozenInstanceError):
        restriction.value = {}


def test_constraints_do_not_invoke_properties_but_policy_does():
    class Resource:
        calls = 0

        @property
        def owner(self):
            self.calls += 1
            return 1

    resource = Resource()
    condition = {"field": "context.resource.owner", "value": 1}
    principal = Principal({}, {}, "test")
    context = AuthorizationContext(resource=resource)
    assert not ConditionConstraint(**condition).check(
        principal, "read", context
    )
    assert resource.calls == 0
    assert Policy([{"permissions": ["read"], "when": condition}]).check(
        principal, "read", context
    )
    assert resource.calls == 1


def test_stored_dataclass_and_slot_values_are_supported():
    @dataclass(slots=True)
    class Resource:
        owner: int

    principal = Principal({"id": 42}, {}, "test")
    restriction = ConditionConstraint(
        "context.resource.owner", value="@subject.id"
    )
    assert restriction.check(
        principal, "read", AuthorizationContext(resource=Resource(42))
    )


def test_special_dict_property_is_not_invoked():
    class Resource:
        @property
        def __dict__(self):
            raise AssertionError("property must not run")

    assert not ConditionConstraint("context.resource.owner", value=1).check(
        Principal({}, {}, "test"),
        "read",
        AuthorizationContext(resource=Resource()),
    )


@pytest.mark.parametrize(
    "pattern",
    ["(a+)+$", "(a|aa)+$", "a*a*a*b", "(?=a)a", r"(a)\1", "a{1000000}"],
)
def test_unsafe_regex_is_rejected_for_constants_and_runtime_refs(pattern):
    with pytest.raises(JamConfigurationError):
        ConditionConstraint("subject.name", "matches", pattern)
    restriction = ConditionConstraint(
        "subject.name", "matches", "@context.attributes.pattern"
    )
    assert not restriction.check(
        Principal({"name": "a" * 100}, {}, "test"),
        "read",
        AuthorizationContext(attributes={"pattern": pattern}),
    )


def test_regex_limits_and_valid_runtime_reference():
    assert not check("matches", "a*", "a" * 4097)
    with pytest.raises(JamConfigurationError):
        ConditionConstraint("subject.name", "matches", "a" * 257)
    restriction = ConditionConstraint(
        "subject.name", "matches", "@context.attributes.pattern"
    )
    principal = Principal({"name": "owner"}, {}, "test")
    assert restriction.check(
        principal,
        "read",
        AuthorizationContext(attributes={"pattern": "admin|owner"}),
    )
    assert not restriction.check(
        principal, "read", AuthorizationContext(attributes={"pattern": "["})
    )


def test_policy_regex_language_is_unchanged():
    policy = Policy(
        [
            {
                "permissions": ["read"],
                "when": {
                    "field": "subject.role",
                    "operator": "matches",
                    "value": "(admin|owner)",
                },
            }
        ]
    )
    assert policy.check({"role": "admin"}, "read")


@pytest.mark.parametrize(
    ("pattern", "permission", "allowed"),
    [
        ("*", "documents:read", True),
        ("documents:*", "documents:read", True),
        ("documents:*", "documents", False),
        ("documents:read", "documents:write", False),
        ("documents:read", "documents:read", True),
    ],
)
def test_permission_wildcards(pattern, permission, allowed):
    restriction = PermissionConstraint(pattern)
    assert (
        restriction.check(
            Principal({}, {}, "test"), permission, AuthorizationContext()
        )
        is allowed
    )


@pytest.mark.parametrize("operator", ["in", "gt", "contains", "between"])
def test_type_mismatch_fails_closed(operator):
    value = [1, 2] if operator == "between" else 1
    assert not check(operator, value, None)
