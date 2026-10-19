"""Structural validation before module construction."""

from typing import Any

from jam.exceptions import JamConfigurationError


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    """Require a dictionary without exposing its contents in diagnostics."""
    if not isinstance(value, dict):
        raise JamConfigurationError(
            message=f"Configuration field '{field}' must be a mapping.",
            error_code="configuration.invalid_structure",
            details={"field": field, "expected": "mapping"},
        )
    return value


def __config_validator__(config: dict[str, Any]) -> bool:
    """Validate known section shapes while preserving extension keys.

    Args:
        config: Selected root configuration.

    Returns:
        True when the structure is valid.

    Raises:
        JamConfigurationError: A known configuration section is malformed.
    """
    _require_mapping(config, "root")
    for section in (
        "jose",
        "session",
        "paseto",
        "saml",
        "otp",
        "authz",
        "oauth2",
        "keychains",
    ):
        value = config.get(section)
        if value is not None:
            _require_mapping(value, section)
    for name, value in (config.get("jose") or {}).items():
        if name in ("jwt", "jws", "jwe") and value is not None:
            _require_mapping(value, f"jose.{name}")
    for section in ("keychains", "oauth2"):
        for name, value in (config.get(section) or {}).items():
            _require_mapping(value, f"{section}.{name}")
    # Lists and macaroons retain their established domain error codes.
    lists = config.get("lists")
    if lists is not None and not isinstance(lists, dict):
        raise JamConfigurationError(
            message="Token lists configuration must be a mapping.",
            error_code="configuration.lists.invalid",
        )
    from jam.aio.lists.__base__ import BaseAsyncList
    from jam.lists.__base__ import BaseList

    if isinstance(lists, dict):
        for name, value in lists.items():
            if not isinstance(value, (BaseList, BaseAsyncList)):
                _require_mapping(value, f"lists.{name}")
    rules = (config.get("authz") or {}).get("rules")
    if rules is not None and not (config.get("authz") or {}).get("module"):
        _require_mapping(rules, "authz.rules")
    credentials = {
        "jose.jwt": (config.get("jose") or {}).get("jwt"),
        "paseto": config.get("paseto"),
        "saml": config.get("saml"),
        "macaroon": config.get("macaroon"),
    }
    for path, section in credentials.items():
        if isinstance(section, dict):
            token_list = section.get("list")
            if token_list is not None and not isinstance(
                token_list, (str, BaseList, BaseAsyncList)
            ):
                _require_mapping(token_list, f"{path}.list")
    return True
