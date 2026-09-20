# -*- coding: utf-8 -*-

"""Authorization contracts and credential data."""

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generic, Protocol, TypeVar

from jam.authz._conditions import permission_matches
from jam.subject import BaseSubject


SubjectT = TypeVar("SubjectT", bound=BaseSubject | Mapping[str, Any])
Subject = BaseSubject | Mapping[str, Any]
Predicate = str | Callable[[Subject], bool]
Condition = Predicate | Mapping[str, Any]
Rule = Mapping[str, Any]
Rules = Mapping[str, Sequence[Predicate]] | Sequence[Rule]


class AuthorizationConstraint(Protocol):
    """A mandatory, side-effect-free restriction on credential authority."""

    def check(
        self,
        principal: "Principal[Any]",
        permission: str,
        context: "AuthorizationContext",
    ) -> bool:
        """Return whether this restriction is satisfied."""
        ...


@dataclass
class Principal(Generic[SubjectT]):
    """Authenticated subject together with the claims of its credential."""

    subject: SubjectT
    claims: dict[str, Any]
    token_type: str
    constraints: tuple[AuthorizationConstraint, ...] = ()

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
            permission_matches(grant, permission) for grant in self.permissions
        )


@dataclass
class AuthorizationContext:
    """Dynamic values available while evaluating authorization rules."""

    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resource: Any = None
    request: Any = None
    attributes: dict[str, Any] = field(default_factory=dict)


CompiledCondition = Callable[[Principal[Any], AuthorizationContext], bool]


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
