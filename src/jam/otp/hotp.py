# -*- coding: utf-8 -*-

import logging

from jam.otp.__base__ import BaseOTP


logger = logging.getLogger(__name__)


class HOTP(BaseOTP):
    """HOTP instance."""

    def at(self, factor: int) -> str:  # type: ignore[override]
        """Generates a HOTP code for the specified counter.

        Args:
            factor (int): Counter (increases after each use).

        Returns:
            str: HOTP code (fixed-length string).
        """
        return str(self._dynamic_truncate(self._hmac(factor))).zfill(
            self.digits
        )

    def verify(self, code: str, factor: int, look_ahead: int = 1) -> bool:  # type: ignore[override]
        """Verify HOTP-code.

        Args:
            code (str): Code.
            factor (int): Now counter.
            look_ahead (int, optional): Allowable forward offset (to compensate for desynchronization). Default is 1..

        Returns:
            bool: True if the code matches, otherwise False.
        """
        for i in range(factor, factor + look_ahead + 1):
            if self.at(i) == code:
                logger.debug(
                    "HOTP verification succeeded with look_ahead=%d",
                    look_ahead,
                )
                return True
        logger.warning("HOTP verification failed with look_ahead=%d", look_ahead)
        return False
