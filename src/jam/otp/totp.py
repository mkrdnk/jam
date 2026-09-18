# -*- coding: utf-8 -*-

import logging
import time
from typing import Literal

from jam.otp.__base__ import BaseOTP


logger = logging.getLogger(__name__)


class TOTP(BaseOTP):
    """TOTP (Time-based One-Time Password, RFC6238)."""

    def __init__(
        self,
        secret: bytes | str,
        digits: int = 6,
        digest: Literal["sha1", "sha256", "sha512"] = "sha1",
        interval: int = 30,
    ) -> None:
        """TOTP initialization.

        Args:
            secret (bytes | str): Secret key.
            digits (int, optional): Number of digits in the code. Default is 6.
            digest (str, optional): Hashing algorithm. Default is "sha1".
            interval (int, optional): Time interval in seconds. Default is 30.
        """
        super().__init__(secret, digits, digest)
        self.interval = interval

    def at(self, factor: int | None = None) -> str:
        """Generates a TOTP code for a specified time.

        Args:
            factor (int | None, optional): Time in UNIX seconds. If None, the current time is used. Default is None.

        Returns:
            str: TOTP code (fixed-length string).
        """
        if factor is None:
            factor = int(time.time())
        counter = factor // self.interval
        return str(self._dynamic_truncate(self._hmac(counter))).zfill(
            self.digits
        )

    @property
    def now(self) -> str:
        """Returns the current TOTP code.

        Returns:
            str: TOTP code for the current time.
        """
        return self.at()

    def verify(
        self, code: str, factor: int | None = None, look_ahead: int = 1
    ) -> bool:
        """Checks the TOTP code, taking into account the acceptable window.

        Args:
            code (str): The code entered.
            factor (int | None, optional): Time in UNIX seconds. If None, the current time. Default is None.
            look_ahead (int, optional): Acceptable deviation in intervals (±window). Default is 1.

        Returns:
            bool: True if the code matches, otherwise False.
        """
        if factor is None:
            factor = int(time.time())
        for offset in range(-look_ahead, look_ahead + 1):
            if self.at(factor + offset * self.interval) == code:
                logger.debug(
                    "TOTP verification succeeded with look_ahead=%d",
                    look_ahead,
                )
                return True
        logger.warning("TOTP verification failed with look_ahead=%d", look_ahead)
        return False
