# -*- coding: utf-8 -*-

"""
*OTP auth module
"""

from typing import Any, Literal

from .__base__ import BaseOTP
from .hotp import HOTP
from .totp import TOTP


def create_instance(
    type: Literal["hotp", "totp"],
    **kwargs: Any,
) -> type[BaseOTP]:
    """Create OTP class (not instance, since secret is provided per-call).

    Args:
        type (str): "hotp" | "totp"
        **kwargs: digits, digest, interval (for TOTP), custom_module

    Returns:
        HOTP or TOTP class
    """
    if kwargs.get("custom_module"):
        from jam.utils.config_maker import __module_loader__

        return __module_loader__(kwargs["custom_module"])  # type: ignore[return-value]

    from jam.utils.config_maker import __module_loader__

    return __module_loader__(f"jam.otp.{type}.{type.upper()}")  # type: ignore[return-value]
