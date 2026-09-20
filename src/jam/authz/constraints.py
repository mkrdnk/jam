# -*- coding: utf-8 -*-

"""Mandatory restrictions on credential authority."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from jam.authz.__base__ import AuthorizationContext, Principal
from jam.authz._conditions import (
    compile_comparison,
    permission_matches,
    snapshot,
    validate_permissions,
)
from jam.authz._errors import _invalid
from jam.authz._roots import _condition_roots


@dataclass(frozen=True)
class PermissionConstraint:
    """Restrict authorization to one permission pattern."""

    permission: str

    def __post_init__(self) -> None:
        """Validate the exact or wildcard permission pattern."""
        validate_permissions([self.permission], _invalid)

    def check(
        self,
        principal: Principal[Any],
        permission: str,
        context: AuthorizationContext,
    ) -> bool:
        """Return whether the requested permission matches the restriction."""
        return permission_matches(self.permission, permission)


@dataclass(frozen=True)
class ConditionConstraint:
    """Restrict authority with one structured comparison.

    Missing fields or references always deny access, even with
    ``exists=False``. Only stored attributes are read, not properties.
    Regex patterns are limited to 256 characters, 16 flat alternatives and
    one repetition (*, +, ?) per branch; groups and braced quantifiers are
    forbidden. Input strings are limited to 4096 characters. These limits
    also apply to regex patterns obtained through runtime references.
    """

    field: str
    operator: str = "eq"
    value: Any = None
    timezone: str | None = None
    _matches: Callable[[Mapping[str, Any]], bool] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Validate and compile the comparison once."""
        object.__setattr__(self, "value", snapshot(self.value, _invalid))
        condition: dict[str, Any] = {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
        }
        if self.timezone is not None:
            condition["timezone"] = self.timezone
        object.__setattr__(
            self,
            "_matches",
            compile_comparison(
                condition,
                _invalid,
                missing_reference_is_error=False,
                untrusted_pattern=True,
                stored_attributes_only=True,
            ),
        )

    def check(
        self,
        principal: Principal[Any],
        permission: str,
        context: AuthorizationContext,
    ) -> bool:
        """Evaluate against subject, token, and authorization context data."""
        return self._matches(
            _condition_roots(principal, context, stored_attributes_only=True)
        )
