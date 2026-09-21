"""Validate configuration for the Jam macaroon profile."""

from collections.abc import Callable, Mapping
from typing import Any

from jam.exceptions import JamConfigurationError
from jam.keychain.__base__ import BaseKeyChain

from .core import Limits
from .profile import CaveatRegistry, MacaroonModule


def create_instance(
    config: Mapping[str, Any],
    *,
    resolve_keychain: Callable[..., BaseKeyChain],
    registry: CaveatRegistry | None = None,
) -> MacaroonModule:
    """Validate all configuration and resolve a named KeyChain."""
    try:
        if not isinstance(config, Mapping):
            raise ValueError
        if set(config) - {
            "keychain",
            "location",
            "limits",
            "issuer",
            "audience",
            "leeway",
        }:
            raise ValueError
        keychain = config.get("keychain")
        location = config.get("location", "")
        issuer = config.get("issuer")
        audience = config.get("audience")
        leeway = config.get("leeway", 0.0)
        if not isinstance(keychain, str) or not keychain:
            raise ValueError
        if not isinstance(location, str):
            raise ValueError
        raw_limits = config.get("limits", {})
        limits = (
            raw_limits
            if isinstance(raw_limits, Limits)
            else Limits(**raw_limits)
        )
        if registry is not None and not isinstance(registry, CaveatRegistry):
            raise ValueError
        chain = resolve_keychain(keychain, "MACAROON-HMAC-SHA256", "local")
        return MacaroonModule(
            chain,
            location=location,
            limits=limits,
            registry=registry,
            issuer=issuer,
            audience=audience,
            leeway=leeway,
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise JamConfigurationError(
            "Invalid macaroon configuration",
            error_code="macaroon.configuration",
        ) from exc
