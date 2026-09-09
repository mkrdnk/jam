# -*- coding: utf-8 -*-

from typing import Any

from jam.exceptions import JamConfigurationError


# TODO: make config validator
def __config_validator__(config: dict[str, Any]) -> bool:
    """Validation config util.

    Args:
        config (dict): Config dict after export from file and without pointer.

    Returns:
        bool: True if config valid
    """
    raise JamConfigurationError(
        message="<error_message>",
        error_code="config.validation_error",
        details={"field": "SOME_FIELD", "value": "SOME_VALUE"},
    )
