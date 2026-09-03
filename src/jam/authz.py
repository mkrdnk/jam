# -*- coding: utf-8 -*-

"""Declarative authorization policies."""

from abc import ABC, abstractmethod
import ast
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, time, timezone
import ipaddress
import operator
import re
from typing import Any, Generic, TypeVar
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from jam.exceptions import JamConfigurationError
from jam.subject import BaseSubject


SubjectT = TypeVar("SubjectT", bound=BaseSubject | Mapping[str, Any])
Subject = BaseSubject | Mapping[str, Any]
Predicate = str | Callable[[Subject], bool]
Condition = Predicate | Mapping[str, Any]
Rule = Mapping[str, Any]
Rules = Mapping[str, Sequence[Predicate]] | Sequence[Rule]
_MISSING = object()


@dataclass
class Principal(Generic[SubjectT]):
    """Authenticated subject together with the claims of its credential."""

    subject: SubjectT
    claims: dict[str, Any]
    token_type: str

    @property
    def permissions(self) -> frozenset[str]:
        """Return permissions declared by this credential."""
        value = self.claims.get("permissions", self.claims.get("scope", ()))
        if isinstance(value, str):
            return frozenset(value.split())
        if isinstance(value, Sequence) and not isinstance(value, bytes):
            return frozenset(item for item in value if isinstance(item, str))
        return frozenset()

    @property
    def jti(self) -> str | None:
        """Return the JWT ID claim, if present."""
        value = self.claims.get("jti")
        return value if isinstance(value, str) else None

    def has_permission(self, permission: str) -> bool:
        """Check whether a credential grant covers a permission."""
        return any(
            _permission_matches(grant, permission) for grant in self.permissions
        )


@dataclass
class AuthorizationContext:
    """Dynamic values available while evaluating authorization rules."""

    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resource: Any = None
    request: Any = None
    attributes: dict[str, Any] = field(default_factory=dict)


CompiledCondition = Callable[[Principal[Any], AuthorizationContext], bool]


@dataclass(frozen=True)
class _PolicyRule:
    effect: str
    permissions: tuple[str, ...]
    matches: CompiledCondition


@dataclass(frozen=True)
class _ConditionOperator:
    evaluate: Callable[[Any, Any], bool]
    validate: Callable[[Any], None] = lambda value: None


def _contains(actual: Any, expected: Any) -> bool:
    return expected in actual


def _contains_any(actual: Any, expected: Any) -> bool:
    return any(item in actual for item in expected)


def _contains_all(actual: Any, expected: Any) -> bool:
    return all(item in actual for item in expected)


def _in(actual: Any, expected: Any) -> bool:
    return actual in expected


def _not_in(actual: Any, expected: Any) -> bool:
    return actual not in expected


def _exists(actual: Any, expected: Any) -> bool:
    return (actual is not _MISSING) is bool(expected)


def _truthy(actual: Any, expected: Any) -> bool:
    return bool(actual)


def _starts_with(actual: Any, expected: Any) -> bool:
    return isinstance(actual, str) and actual.startswith(expected)


def _ends_with(actual: Any, expected: Any) -> bool:
    return isinstance(actual, str) and actual.endswith(expected)


def _matches(actual: Any, expected: Any) -> bool:
    return (
        isinstance(actual, str) and re.fullmatch(expected, actual) is not None
    )


def _ip_in_network(actual: Any, expected: Any) -> bool:
    return ipaddress.ip_address(actual) in ipaddress.ip_network(expected)


def _between(actual: Any, expected: Any) -> bool:
    lower, upper = expected
    if isinstance(actual, datetime) and all(
        isinstance(item, str) for item in expected
    ):
        current = actual.timetz().replace(tzinfo=None)
        start = time.fromisoformat(lower)
        end = time.fromisoformat(upper)
        if start <= end:
            return start <= current < end
        return current >= start or current < end
    return lower <= actual <= upper


def _validate_between(value: Any) -> None:
    if (
        isinstance(value, str)
        or not isinstance(value, Sequence)
        or len(value) != 2
    ):
        _invalid("'between' requires exactly two values.")


def _validate_regex(value: Any) -> None:
    try:
        re.compile(value)
    except (TypeError, re.error) as error:
        _invalid(f"Invalid regular expression: {error}")


_OPERATORS = {
    "exists": _ConditionOperator(_exists),
    "truthy": _ConditionOperator(_truthy),
    "eq": _ConditionOperator(operator.eq),
    "ne": _ConditionOperator(operator.ne),
    "in": _ConditionOperator(_in),
    "not_in": _ConditionOperator(_not_in),
    "contains": _ConditionOperator(_contains),
    "contains_any": _ConditionOperator(_contains_any),
    "contains_all": _ConditionOperator(_contains_all),
    "starts_with": _ConditionOperator(_starts_with),
    "ends_with": _ConditionOperator(_ends_with),
    "matches": _ConditionOperator(_matches, _validate_regex),
    "ip_in_network": _ConditionOperator(_ip_in_network),
    "between": _ConditionOperator(_between, _validate_between),
    "gt": _ConditionOperator(operator.gt),
    "gte": _ConditionOperator(operator.ge),
    "lt": _ConditionOperator(operator.lt),
    "lte": _ConditionOperator(operator.le),
}


class BasePolicy(ABC):
    """Base policy contract."""

    @abstractmethod
    def check(
        self,
        principal: Principal[Any] | Subject,
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Check whether a principal may perform a permission.

        Args:
            principal: Authenticated principal, subject or subject mapping.
            permission: Permission name, e.g. ``"post:edit"``.
            context: Dynamic authorization context.

        Returns:
            bool: True if allowed, False otherwise.
        """
        raise NotImplementedError


class Policy(BasePolicy):
    """Declarative allow/deny policy.

    Supports compact ``{permission: [predicates]}`` and structured rules.
    Deny rules always take precedence; unmatched permissions are denied.
    """

    def __init__(self, rules: Rules | None = None, **kwargs: Any) -> None:
        """Compile and validate policy rules.

        Args:
            rules: Compact permission mapping or structured rules.
            **kwargs: Ignored for config compatibility.
        """
        self._rules = _RuleCompiler.compile(rules or {})

    def check(
        self,
        principal: Principal[Any] | Subject,
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Evaluate credential grants and matching policy rules."""
        if not isinstance(permission, str) or not permission:
            _invalid("Permission must be a non-empty string.")

        authenticated = (
            principal
            if isinstance(principal, Principal)
            else Principal(principal, {}, "subject")
        )
        matching = [
            rule
            for rule in self._rules
            if any(
                _permission_matches(pattern, permission)
                for pattern in rule.permissions
            )
        ]
        grants_declared = any(
            claim in authenticated.claims for claim in ("permissions", "scope")
        )
        if grants_declared and not authenticated.has_permission(permission):
            return False

        auth_context = context or AuthorizationContext()
        if any(
            rule.effect == "deny" and rule.matches(authenticated, auth_context)
            for rule in matching
        ):
            return False

        allow_rules = [rule for rule in matching if rule.effect == "allow"]
        if allow_rules:
            return any(
                rule.matches(authenticated, auth_context)
                for rule in allow_rules
            )
        return grants_declared and authenticated.has_permission(permission)


class _RuleCompiler:
    """Compile config mappings into immutable runtime policy rules."""

    @classmethod
    def compile(cls, rules: Rules) -> tuple[_PolicyRule, ...]:
        """Compile either supported rule representation."""
        if isinstance(rules, Mapping):
            return cls._compile_compact(rules)
        if isinstance(rules, str) or not isinstance(rules, Sequence):
            _invalid("Rules must be a mapping or a list.")
        return cls._compile_structured(rules)

    @classmethod
    def _compile_compact(
        cls,
        rules: Mapping[str, Sequence[Predicate]],
    ) -> tuple[_PolicyRule, ...]:
        compiled = []
        for permission, predicates in rules.items():
            _validate_permissions([permission])
            if isinstance(predicates, str) or not isinstance(
                predicates, Sequence
            ):
                _invalid("Predicates must be a list.")
            conditions = tuple(
                cls._compile_condition(predicate) for predicate in predicates
            )
            compiled.append(
                _PolicyRule(
                    "allow",
                    (permission,),
                    lambda principal, context, conditions=conditions: any(
                        condition(principal, context)
                        for condition in conditions
                    ),
                )
            )
        return tuple(compiled)

    @classmethod
    def _compile_structured(
        cls,
        rules: Sequence[Rule],
    ) -> tuple[_PolicyRule, ...]:
        return tuple(cls._compile_rule(rule) for rule in rules)

    @classmethod
    def _compile_rule(cls, rule: Rule) -> _PolicyRule:
        if not isinstance(rule, Mapping):
            _invalid("Each authorization rule must be a mapping.")

        effect = rule.get("effect", "allow")
        if effect not in {"allow", "deny"}:
            _invalid("Rule effect must be 'allow' or 'deny'.")

        permissions = rule.get("permissions")
        if isinstance(permissions, str):
            permissions = [permissions]
        if not isinstance(permissions, Sequence) or not permissions:
            _invalid("Rule permissions must be a non-empty list.")
        _validate_permissions(permissions)

        condition = rule.get("when")
        matches = (
            cls._compile_condition(condition)
            if condition is not None
            else lambda principal, context: True
        )
        return _PolicyRule(effect, tuple(permissions), matches)

    @classmethod
    def _compile_condition(cls, condition: Any) -> CompiledCondition:
        if callable(condition):
            return lambda principal, context: bool(condition(principal.subject))
        if isinstance(condition, str):
            return cls._compile_compact_predicate(condition)
        if not isinstance(condition, Mapping):
            _invalid("A condition must be a string, callable or mapping.")

        logical_keys = tuple(
            key for key in ("all", "any", "not") if key in condition
        )
        if logical_keys:
            return cls._compile_logical(condition, logical_keys)
        return cls._compile_comparison(condition)

    @classmethod
    def _compile_logical(
        cls,
        condition: Mapping[str, Any],
        logical_keys: tuple[str, ...],
    ) -> CompiledCondition:
        if len(logical_keys) != 1 or len(condition) != 1:
            _invalid("A logical condition must have exactly one key.")

        key = logical_keys[0]
        value = condition[key]
        if key == "not":
            child = cls._compile_condition(value)
            return lambda principal, context: not child(principal, context)
        if isinstance(value, str) or not isinstance(value, Sequence):
            _invalid(f"'{key}' must contain a list.")

        children = tuple(cls._compile_condition(item) for item in value)
        reducer = all if key == "all" else any
        return lambda principal, context: reducer(
            child(principal, context) for child in children
        )

    @staticmethod
    def _compile_compact_predicate(predicate: str) -> CompiledCondition:
        if predicate == "*":
            return lambda principal, context: True

        field_name, separator, raw_value = predicate.partition("=")
        path = field_name.strip()
        if not _valid_path(path):
            _invalid(f"Invalid subject field: {path}")

        expected = _parse_literal(raw_value) if separator else _MISSING

        def matches(
            principal: Principal[Any],
            context: AuthorizationContext,
        ) -> bool:
            actual = _resolve(_subject_data(principal.subject), path.split("."))
            if actual is _MISSING:
                return False
            return actual == expected if separator else bool(actual)

        return matches

    @staticmethod
    def _compile_comparison(
        condition: Mapping[str, Any],
    ) -> CompiledCondition:
        path = condition.get("field")
        if not isinstance(path, str) or not _valid_path(
            path, require_root=True
        ):
            _invalid(f"Invalid authorization field: {path}")

        operator_name = condition.get("operator", "eq")
        condition_operator = _OPERATORS.get(operator_name)
        if condition_operator is None:
            _invalid(f"Unknown authorization operator: {operator_name}")

        expected = condition.get("value")
        condition_operator.validate(expected)
        selected_timezone = _compile_timezone(condition.get("timezone"))

        def matches(
            principal: Principal[Any],
            context: AuthorizationContext,
        ) -> bool:
            actual = _resolve(
                _condition_roots(principal, context),
                path.split("."),
            )
            if selected_timezone is not None and isinstance(actual, datetime):
                actual = actual.astimezone(selected_timezone)
            try:
                return condition_operator.evaluate(actual, expected)
            except (TypeError, ValueError, re.error):
                return False

        return matches


def _condition_roots(
    principal: Principal[Any],
    context: AuthorizationContext,
) -> dict[str, Any]:
    return {
        "subject": _subject_data(principal.subject),
        "token": principal.claims,
        "context": {
            "time": context.now,
            "now": context.now,
            "resource": context.resource,
            "request": context.request,
            "attributes": context.attributes,
        },
    }


def _compile_timezone(value: Any) -> ZoneInfo | None:
    if value is None:
        return None
    try:
        return ZoneInfo(str(value))
    except ZoneInfoNotFoundError as error:
        raise JamConfigurationError(
            message=f"Unknown timezone: {value}",
            error_code="configuration.authz.invalid_rule",
        ) from error


def _permission_matches(pattern: str, permission: str) -> bool:
    if pattern == "*" or pattern == permission:
        return True
    return pattern.endswith(":*") and permission.startswith(f"{pattern[:-2]}:")


def _validate_permissions(permissions: Sequence[Any]) -> None:
    for permission in permissions:
        if not isinstance(permission, str) or not permission:
            _invalid("Permissions must be non-empty strings.")
        if (
            "*" in permission
            and permission != "*"
            and not permission.endswith(":*")
        ):
            _invalid(f"Invalid permission wildcard: {permission}")


def _subject_data(subject: Subject) -> Mapping[str, Any]:
    if isinstance(subject, Mapping):
        return subject
    if is_dataclass(subject):
        return asdict(subject)
    return {}


def _resolve(value: Any, path: Sequence[str]) -> Any:
    current = value
    for part in path:
        if not part or part.startswith("_"):
            return _MISSING
        if isinstance(current, Mapping):
            current = current.get(part, _MISSING)
        elif is_dataclass(current):
            names = {item.name for item in fields(current)}
            current = getattr(current, part) if part in names else _MISSING
        else:
            return _MISSING
        if current is _MISSING:
            return _MISSING
    return current


def _parse_literal(value: str) -> Any:
    value = value.strip()
    constants = {"true": True, "false": False, "null": None}
    if value.lower() in constants:
        return constants[value.lower()]
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value


def _valid_path(path: str, require_root: bool = False) -> bool:
    parts = path.split(".")
    valid = parts and all(
        part.isidentifier() and not part.startswith("_") for part in parts
    )
    return bool(
        valid
        and (not require_root or parts[0] in {"subject", "token", "context"})
    )


def _invalid(message: str) -> None:
    raise JamConfigurationError(
        message=message,
        error_code="configuration.authz.invalid_rule",
    )
