# -*- coding: utf-8 -*-

"""Declarative authorization policies."""

from abc import ABC, abstractmethod
import ast
from collections.abc import Callable
from typing import Any

from jam.subject import BaseSubject


Predicate = str | Callable[[BaseSubject], bool]


class BasePolicy(ABC):
    """Base policy contract.

    Implementations decide whether ``subject`` may perform ``permission``.
    """

    @abstractmethod
    def check(self, subject: BaseSubject, permission: str) -> bool:
        """Check whether a subject is allowed to perform a permission.

        Args:
            subject (BaseSubject): Subject instance.
            permission (str): Permission name, e.g. ``"post:edit"``.

        Returns:
            bool: True if allowed, False otherwise.
        """
        raise NotImplementedError


class Policy(BasePolicy):
    """Declarative policy built from rules.

    Rules map a permission to a list of predicates. A subject is granted a
    permission if any predicate matches. Deny by default.

    Predicate forms:
        * ``"*"`` — allow every subject.
        * ``"field=value"`` — allow if ``subject.field == value``.
        * ``"field"`` — allow if ``subject.field`` is truthy.
        * A callable receiving the subject and returning bool.

    Example::

        Policy(rules={"post:read": ["*"], "post:edit": ["author_id=42"]})
    """

    def __init__(
        self,
        rules: dict[str, list[Predicate]] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the policy.

        Args:
            rules (dict[str, list[Predicate]] | None): Rules mapping permissions
                to predicate lists. Defaults to None.
            **kwargs: Ignored (config compatibility).
        """
        self._rules: dict[str, list[Predicate]] = rules or {}

    def check(self, subject: BaseSubject, permission: str) -> bool:
        """Check a subject against the configured rules.

        Args:
            subject (BaseSubject): Subject instance.
            permission (str): Permission name.

        Returns:
            bool: True if allowed, False otherwise.
        """
        predicates = self._rules.get(permission)
        if not predicates:
            return False
        return any(self._match(subject, predicate) for predicate in predicates)

    @staticmethod
    def _match(subject: BaseSubject, predicate: Predicate) -> bool:
        """Match a single predicate against a subject.

        Args:
            subject (BaseSubject): Subject instance.
            predicate (Predicate): Predicate to evaluate.

        Returns:
            bool: Match result.
        """
        if callable(predicate):
            return bool(predicate(subject))
        if predicate == "*":
            return True
        if "=" in predicate:
            field, value = predicate.split("=", 1)
            try:
                value = ast.literal_eval(value)
            except (ValueError, SyntaxError):
                pass
            return getattr(subject, field, None) == value
        return bool(getattr(subject, predicate, None))
