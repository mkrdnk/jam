# -*- coding: utf-8 -*-

"""Declarative authorization policies."""

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import logging
from typing import Any, cast

from jam.authz.__base__ import (
    AuthorizationContext,
    BasePolicy,
    CompiledCondition,
    Predicate,
    Principal,
    Rule,
    Rules,
    Subject,
)
from jam.authz._conditions import (
    MISSING,
    compile_comparison,
    permission_matches,
    resolve,
    valid_path,
    validate_permissions,
)
from jam.authz._errors import _invalid
from jam.authz._roots import _condition_roots, _subject_data


logger = logging.getLogger("jam.authz")
_MISSING = MISSING


@dataclass(frozen=True)
class _PolicyRule:
    effect: str
    permissions: tuple[str, ...]
    matches: CompiledCondition


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
        logger.info(
            "Initialized authorization policy with rule_count=%d",
            len(self._rules),
        )

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
                permission_matches(pattern, permission)
                for pattern in rule.permissions
            )
        ]
        grants_declared = any(
            claim in authenticated.claims for claim in ("permissions", "scope")
        )
        if grants_declared and not authenticated.has_permission(permission):
            logger.warning(
                "Authorization denied for permission=%s: credential grant missing",
                permission,
            )
            return False

        auth_context = context or AuthorizationContext()
        if any(
            rule.effect == "deny" and rule.matches(authenticated, auth_context)
            for rule in matching
        ):
            logger.warning(
                "Authorization denied for permission=%s: deny rule matched",
                permission,
            )
            return False

        allow_rules = [rule for rule in matching if rule.effect == "allow"]
        if allow_rules:
            allowed = any(
                rule.matches(authenticated, auth_context)
                for rule in allow_rules
            )
            if allowed:
                logger.debug(
                    "Authorization granted for permission=%s by allow rule",
                    permission,
                )
            else:
                logger.warning(
                    "Authorization denied for permission=%s: no allow rule matched",
                    permission,
                )
            return allowed

        allowed = grants_declared and authenticated.has_permission(permission)
        if allowed:
            logger.debug(
                "Authorization granted for permission=%s by credential grant",
                permission,
            )
        else:
            logger.warning(
                "Authorization denied for permission=%s: no matching rule",
                permission,
            )
        return allowed


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
            validate_permissions([permission], _invalid)
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
        permissions = cast(Sequence[str], permissions)
        validate_permissions(permissions, _invalid)

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
        if not valid_path(path):
            _invalid(f"Invalid subject field: {path}")

        expected = _parse_literal(raw_value) if separator else _MISSING

        def matches(
            principal: Principal[Any],
            context: AuthorizationContext,
        ) -> bool:
            actual = resolve(_subject_data(principal.subject), path.split("."))
            if actual is _MISSING:
                return False
            return actual == expected if separator else bool(actual)

        return matches

    @staticmethod
    def _compile_comparison(
        condition: Mapping[str, Any],
    ) -> CompiledCondition:
        comparison = compile_comparison(
            condition,
            _invalid,
            missing_reference_is_error=True,
        )

        return lambda principal, context: comparison(
            _condition_roots(principal, context)
        )


def _parse_literal(value: str) -> Any:
    value = value.strip()
    constants = {"true": True, "false": False, "null": None}
    if value.lower() in constants:
        return constants[value.lower()]
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value
