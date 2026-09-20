"""Macaroon module and optional Jam claims and constraints profile."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from itertools import islice
import json
from typing import Any

from jam.authz import (
    AuthorizationConstraint,
    ConditionConstraint,
    PermissionConstraint,
)
from jam.exceptions import JamConfigurationError
from jam.exceptions.macaroons import (
    InvalidCaveatError,
    SerializationError,
    VerificationError,
)
from jam.keychain.__base__ import BaseKeyChain

from .__base__ import BaseMacaroon
from .core import (
    DEFAULT_LIMITS,
    Caveat,
    Limits,
    Macaroon,
    VerificationResult,
    Verifier,
    _canonical,
)


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise InvalidCaveatError("Time boundary must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except ValueError as error:
        raise InvalidCaveatError(
            "Invalid time boundary or missing timezone"
        ) from error


class CaveatRegistry:
    """Registry of allowed structured constraints for the Jam profile."""

    def __init__(self) -> None:
        """Create a registry with built-in compilers."""
        self._custom: dict[str, Callable[[Any], AuthorizationConstraint]] = {}

    def register(
        self, name: str, compiler: Callable[[Any], AuthorizationConstraint]
    ) -> CaveatRegistry:
        """Register a compiler returning an authorization constraint."""
        if (
            not isinstance(name, str)
            or not name
            or name in {"permission", "condition", "expires_at", "not_before"}
            or not callable(compiler)
        ):
            raise InvalidCaveatError("Invalid caveat compiler")
        self._custom[name] = compiler
        return self

    def compile(self, caveat: Caveat) -> AuthorizationConstraint:
        """Validate the caveat shape and compile a constraint."""
        try:
            name, value = caveat.name, caveat.value
            if name == "permission":
                if not isinstance(value, str) or not value:
                    raise ValueError
                return PermissionConstraint(value)
            if name == "condition":
                if (
                    not isinstance(value, dict)
                    or not {"field"} <= value.keys()
                    or value.keys() - {"field", "operator", "value", "timezone"}
                    or not isinstance(value["field"], str)
                    or not value["field"]
                    or not isinstance(value.get("operator", "eq"), str)
                    or (
                        "timezone" in value
                        and not isinstance(value["timezone"], str)
                    )
                    or (
                        value.get("operator", "eq") not in {"exists", "truthy"}
                        and "value" not in value
                    )
                ):
                    raise ValueError
                return ConditionConstraint(**value)
            if name in {"expires_at", "not_before"}:
                return ConditionConstraint(
                    field="context.now",
                    operator="lt" if name == "expires_at" else "gte",
                    value=_timestamp(value),
                )
            compiler = self._custom.get(name)
            if compiler is None:
                raise InvalidCaveatError("Unknown caveat")
            constraint = compiler(value)
            if not callable(getattr(constraint, "check", None)):
                raise ValueError
            return constraint
        except InvalidCaveatError:
            raise
        except Exception as exc:
            raise InvalidCaveatError("Invalid caveat") from exc


class MacaroonModule(BaseMacaroon):
    """Explicit-key protocol operations with an optional managed-key profile."""

    def __init__(
        self,
        keychain: BaseKeyChain | None = None,
        *,
        location: str = "",
        limits: Limits = DEFAULT_LIMITS,
        registry: CaveatRegistry | None = None,
    ) -> None:
        """Configure limits and optional Jam profile keys and registry."""
        if (
            keychain is not None
            and keychain.algorithm != "MACAROON-HMAC-SHA256"
        ):
            raise JamConfigurationError(
                "Incompatible KeyChain algorithm",
                error_code="configuration.macaroon.invalid_keychain",
            )
        if not isinstance(location, str):
            raise JamConfigurationError(
                "Location must be a string",
                error_code="configuration.macaroon.invalid_location",
            )
        try:
            location.encode("utf-8")
        except UnicodeEncodeError as error:
            raise JamConfigurationError(
                "Invalid location string",
                error_code="configuration.macaroon.invalid_location",
            ) from error
        if registry is not None and not isinstance(registry, CaveatRegistry):
            raise JamConfigurationError("Invalid caveat registry")
        self.keychain = keychain
        self.location = location
        self.limits = limits
        self.registry = registry if registry is not None else CaveatRegistry()
        self.verifier = Verifier(limits)

    def encode(
        self,
        identifier: bytes | str,
        root_key: bytes | str,
        *,
        location: str = "",
    ) -> str:
        """Create a protocol token with an explicit key and opaque identifier."""
        return Macaroon.create(root_key, identifier, location).encode(
            self.limits
        )

    def verify(
        self,
        token: bytes | str | Macaroon,
        root_key: bytes | str,
        discharges: Iterable[bytes | str | Macaroon] = (),
        *,
        structured_satisfiers: Mapping[str, Callable[[Any], bool]]
        | None = None,
        collect_structured: bool = False,
    ) -> VerificationResult:
        """Verify a protocol token without interpreting Jam profile claims."""
        primary = token if isinstance(token, Macaroon) else self.decode(token)
        supplied = tuple(islice(discharges, self.limits.discharge_count + 1))
        if len(supplied) > self.limits.discharge_count:
            raise VerificationError("Too many discharges")
        decoded = tuple(
            item if isinstance(item, Macaroon) else self.decode(item)
            for item in supplied
        )
        return self.verifier.verify(
            primary,
            root_key,
            decoded,
            structured_satisfiers=structured_satisfiers,
            collect_structured=collect_structured,
        )

    def _profile_keychain(self) -> BaseKeyChain:
        """Require managed keys only for the Jam-specific profile operations."""
        if self.keychain is None:
            raise JamConfigurationError(
                "Jam macaroon profile operations require a KeyChain",
                error_code="configuration.macaroon.missing_keychain",
            )
        return self.keychain

    def satisfy_exact(self, caveat: str | bytes) -> None:
        """Register an accepted opaque predicate."""
        self.verifier.satisfy_exact(caveat)

    def satisfy_general(self, satisfier: Callable[[bytes], bool]) -> None:
        """Register an opaque predicate callback."""
        self.verifier.satisfy_general(satisfier)

    def issue(
        self,
        claims: Mapping[str, Any],
        *,
        exp: int | None = None,
        iss: str | None = None,
        aud: str | None = None,
        nbf: int | None = None,
        jti: str | None = None,
    ) -> str:
        """Issue a Jam profile token with claims in its signed identifier."""
        keychain = self._profile_keychain()
        values = dict(claims)
        if "exp" in values or "nbf" in values:
            raise JamConfigurationError(
                "exp and nbf must be separate arguments, not root claims"
            )
        now = datetime.now(timezone.utc)
        boundaries: list[Caveat] = []
        for seconds, name in ((exp, "expires_at"), (nbf, "not_before")):
            if seconds is not None:
                if type(seconds) is not int:
                    raise JamConfigurationError(
                        "exp and nbf must be integer seconds"
                    )
                try:
                    boundary = now + timedelta(seconds=seconds)
                except OverflowError as error:
                    raise JamConfigurationError(
                        "Time boundary is out of range"
                    ) from error
                boundaries.append(Caveat(name, boundary.isoformat()))
        for name, value in (
            ("iss", iss),
            ("aud", aud),
            ("jti", jti),
        ):
            if value is not None:
                values[name] = value
        kid, key = keychain._material_for_issue()
        try:
            identifier = _canonical(
                {"version": 1, "kid": kid, "claims": values}
            )
        except (TypeError, ValueError) as exc:
            raise SerializationError("Claims must be JSON") from exc
        token = Macaroon.create(key, identifier, self.location)
        for caveat in boundaries:
            token = token.add_caveat(caveat)
        return token.encode(self.limits)

    def decode(self, token: str | bytes) -> Macaroon:
        """Decode the standard transport without authentication."""
        return Macaroon.decode(token, self.limits)

    def authenticate(
        self,
        token: str | bytes | Macaroon,
        discharges: Iterable[str | bytes | Macaroon] = (),
    ) -> tuple[dict[str, Any], tuple[AuthorizationConstraint, ...]]:
        """Verify the entire graph before interpreting Jam profile caveats."""
        keychain = self._profile_keychain()
        primary = (
            self.decode(token) if not isinstance(token, Macaroon) else token
        )
        if len(primary.identifier) > self.limits.serialized_size:
            raise VerificationError("Root identifier is too large")
        # Use the header only for key selection; claims remain untrusted.
        try:
            root = json.loads(primary.identifier)
            if (
                not isinstance(root, dict)
                or set(root) != {"version", "kid", "claims"}
                or type(root["version"]) is not int
                or root["version"] != 1
                or not isinstance(root["kid"], str)
                or not isinstance(root["claims"], dict)
                or _canonical(root) != primary.identifier
            ):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise VerificationError("Invalid root identifier") from exc
        supplied = tuple(islice(discharges, self.limits.discharge_count + 1))
        if len(supplied) > self.limits.discharge_count:
            raise VerificationError("Too many discharges")
        decoded = tuple(
            item if isinstance(item, Macaroon) else self.decode(item)
            for item in supplied
        )
        result = self.verifier.verify(
            primary,
            keychain._material_for_verify(root["kid"]),
            decoded,
            collect_structured=True,
        )
        constraints: list[AuthorizationConstraint] = []
        for caveat in result.caveats:
            constraint = self.registry.compile(caveat)
            constraints.append(constraint)
        return root["claims"], tuple(constraints)
