# -*- coding: utf-8 -*-

"""Shared authorization configuration errors."""

from jam.exceptions import JamConfigurationError


def _invalid(message: str) -> None:
    raise JamConfigurationError(
        message=message,
        error_code="configuration.authz.invalid_rule",
    )
