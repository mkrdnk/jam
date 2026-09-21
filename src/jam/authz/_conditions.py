# -*- coding: utf-8 -*-

"""Shared comparison primitives for policies and constraints."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, time, timezone
import ipaddress
import operator
import re
from types import GetSetDescriptorType, MappingProxyType, MemberDescriptorType
from typing import Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


MISSING = object()
InvalidCondition = Callable[[str], None]
CompiledComparison = Callable[[Mapping[str, Any]], bool]


class _FrozenList(tuple):
    """Mark a frozen list while preserving list semantics for comparisons."""


def snapshot(value: Any, invalid: InvalidCondition) -> Any:
    """Copy and freeze constraint values without executing user code."""
    if type(value) in (
        str,
        bytes,
        int,
        float,
        bool,
        type(None),
        datetime,
        time,
    ):
        return value
    if type(value) is dict:
        return MappingProxyType(
            {
                snapshot(k, invalid): snapshot(v, invalid)
                for k, v in value.items()
            }
        )
    if type(value) in (list, tuple):
        items = tuple(snapshot(item, invalid) for item in value)
        return _FrozenList(items) if type(value) is list else items
    if type(value) in (set, frozenset):
        return frozenset(snapshot(item, invalid) for item in value)
    invalid("Unsupported authorization constraint value.")
    raise AssertionError("invalid callback must raise")


def _comparison_value(value: Any) -> Any:
    if isinstance(value, _FrozenList):
        return [_comparison_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_comparison_value(item) for item in value)
    if isinstance(value, Mapping):
        return {key: _comparison_value(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class _ConditionOperator:
    evaluate: Callable[[Any, Any], bool]


def _inert(value: Any, depth: int = 0) -> bool:
    """Exclude user-defined dunder methods from caveat comparisons."""
    if depth > 32:
        return False
    kind = type(value)
    if kind in (str, bytes, int, float, bool, type(None)):
        return True
    if kind in (datetime, time):
        return value.tzinfo is None or type(value.tzinfo) in (
            timezone,
            ZoneInfo,
        )
    if kind in (list, tuple, set, frozenset):
        return all(_inert(item, depth + 1) for item in value)
    if kind is dict:
        return all(
            _inert(key, depth + 1) and _inert(item, depth + 1)
            for key, item in value.items()
        )
    return False


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
    return (actual is not MISSING) is bool(expected)


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
    "matches": _ConditionOperator(_matches),
    "ip_in_network": _ConditionOperator(_ip_in_network),
    "between": _ConditionOperator(_between),
    "gt": _ConditionOperator(operator.gt),
    "gte": _ConditionOperator(operator.ge),
    "lt": _ConditionOperator(operator.lt),
    "lte": _ConditionOperator(operator.le),
}


def _safe_pattern(pattern: Any) -> bool:
    """Allow a restricted regex subset without explosive backtracking.

    Patterns allow up to 256 characters, no groups or backreferences, at
    most one repetition (*, +, ?) per branch and 16 flat alternatives.
    Braced quantifiers are not supported.
    This deliberately limits the language rather than timing out the re
    engine; server-side policies still accept ordinary regular expressions.
    """
    if type(pattern) is not str or len(pattern) > 256:
        return False
    escaped = False
    in_class = False
    repeats = 0
    branches = 1
    for char in pattern:
        if escaped:
            if char.isdigit() or char in "gN":
                return False
            escaped = False
        elif char == "\\":
            escaped = True
        elif in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char in "(){}":
            return False
        elif char == "|":
            branches += 1
            repeats = 0
            if branches > 16:
                return False
        elif char in "*+?":
            repeats += 1
            if repeats > 1:
                return False
    return not escaped and not in_class


def compile_comparison(
    condition: Mapping[str, Any],
    invalid: InvalidCondition,
    *,
    missing_reference_is_error: bool,
    untrusted_pattern: bool = False,
    stored_attributes_only: bool = False,
) -> CompiledComparison:
    """Validate and compile a field comparison with a constant or reference."""
    raw_path = condition.get("field")
    if not isinstance(raw_path, str) or not valid_path(
        raw_path, require_root=True
    ):
        invalid(f"Invalid authorization field: {raw_path}")
    path = str(raw_path)
    operator_name = condition.get("operator", "eq")
    condition_operator = (
        _OPERATORS.get(operator_name)
        if isinstance(operator_name, str)
        else None
    )
    if condition_operator is None:
        invalid(f"Unknown authorization operator: {operator_name}")
        raise AssertionError("invalid callback must raise")
    raw_value = condition.get("value")
    ref_path = None
    if isinstance(raw_value, str) and raw_value.startswith("@"):
        ref_path = raw_value[1:]
    if ref_path is not None and not valid_path(ref_path, require_root=True):
        invalid(f"Invalid authorization value reference: {raw_value}")
    if ref_path is None:
        if (
            untrusted_pattern
            and operator_name == "matches"
            and not _safe_pattern(raw_value)
        ):
            invalid("Unsafe authorization regular expression.")
        _validate_operator_value(operator_name, raw_value, invalid)
    selected_timezone = compile_timezone(condition.get("timezone"), invalid)

    def matches(roots: Mapping[str, Any]) -> bool:
        actual = resolve(
            roots,
            path.split("."),
            stored_attributes_only=stored_attributes_only,
        )
        if ref_path is not None:
            expected = resolve(
                roots,
                ref_path.split("."),
                stored_attributes_only=stored_attributes_only,
            )
            if expected is MISSING:
                if missing_reference_is_error:
                    invalid(
                        "Authorization value reference has no value: "
                        f"{raw_value}"
                    )
                return False
        else:
            expected = (
                _comparison_value(raw_value)
                if stored_attributes_only
                else raw_value
            )
        if actual is MISSING and (
            stored_attributes_only or operator_name != "exists"
        ):
            return False
        if stored_attributes_only and (
            not _inert(actual) or not _inert(expected)
        ):
            return False
        if untrusted_pattern and operator_name == "matches":
            if (
                not _safe_pattern(expected)
                or type(actual) is not str
                or len(actual) > 4096
            ):
                return False
        try:
            if selected_timezone is not None and isinstance(actual, datetime):
                actual = actual.astimezone(selected_timezone)
            return condition_operator.evaluate(actual, expected)
        except (TypeError, ValueError, re.error):
            return False
        except OverflowError:
            if stored_attributes_only:
                return False
            raise

    return matches


def _validate_operator_value(
    operator_name: Any,
    value: Any,
    invalid: InvalidCondition,
) -> None:
    if operator_name == "between" and (
        isinstance(value, str)
        or not isinstance(value, Sequence)
        or len(value) != 2
    ):
        invalid("'between' requires exactly two values.")
    if operator_name == "matches":
        try:
            re.compile(value)
        except (TypeError, re.error) as error:
            invalid(f"Invalid regular expression: {error}")


def compile_timezone(value: Any, invalid: InvalidCondition) -> ZoneInfo | None:
    """Validate an optional IANA timezone."""
    if value is None:
        return None
    try:
        return ZoneInfo(str(value))
    except ZoneInfoNotFoundError:
        invalid(f"Unknown timezone: {value}")
        raise AssertionError("invalid callback must raise")


def permission_matches(pattern: str, permission: str) -> bool:
    """Match an exact permission or wildcard pattern."""
    if pattern == "*" or pattern == permission:
        return True
    return pattern.endswith(":*") and permission.startswith(f"{pattern[:-2]}:")


def validate_permissions(
    permissions: Sequence[Any], invalid: InvalidCondition
) -> None:
    """Validate permissions using the server-side policy syntax."""
    for permission in permissions:
        if not isinstance(permission, str) or not permission:
            invalid("Permissions must be non-empty strings.")
        if (
            "*" in permission
            and permission != "*"
            and not permission.endswith(":*")
        ):
            invalid(f"Invalid permission wildcard: {permission}")


def _stored_attribute(value: object, name: str) -> Any:
    # Never invoke properties, __getattr__, or custom __getattribute__ methods.
    namespace = {}
    for cls in type(value).__mro__:
        descriptor = vars(cls).get("__dict__", MISSING)
        if type(descriptor) is GetSetDescriptorType:
            namespace = descriptor.__get__(value, type(value))
            break
        if descriptor is not MISSING:
            break
    if type(namespace) is dict and name in namespace:
        return namespace[name]
    for cls in type(value).__mro__:
        descriptor = vars(cls).get(name, MISSING)
        if type(descriptor) is MemberDescriptorType:
            try:
                return descriptor.__get__(value, type(value))
            except AttributeError:
                return MISSING
        if descriptor is not MISSING:
            return MISSING
    return MISSING


def resolve(
    value: object,
    path: Sequence[str],
    *,
    stored_attributes_only: bool = False,
) -> Any:
    """Resolve a path; for caveats, read stored data rather than properties."""
    current: object = value
    for part in path:
        if not part or part.startswith("_"):
            return MISSING
        if stored_attributes_only:
            if type(current) in (dict, MappingProxyType):
                current = cast(Mapping[str, Any], current).get(part, MISSING)
            else:
                current = _stored_attribute(current, part)
        elif isinstance(current, Mapping):
            current = current.get(part, MISSING)
        elif is_dataclass(current):
            names = {item.name for item in fields(current)}
            current = getattr(current, part) if part in names else MISSING
        else:
            try:
                candidate = getattr(current, part, MISSING)
            except Exception:
                return MISSING
            if candidate is MISSING or callable(candidate):
                return MISSING
            current = candidate
        if current is MISSING:
            return MISSING
    return current


def valid_path(path: str, require_root: bool = False) -> bool:
    """Validate a public path and, optionally, its authorization root."""
    parts = path.split(".")
    valid = parts and all(
        part.isidentifier() and not part.startswith("_") for part in parts
    )
    return bool(
        valid
        and (not require_root or parts[0] in {"subject", "token", "context"})
    )
