# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
import logging
import os
from typing import Any, Literal


class BaseLogger(ABC):
    """Interface for logging."""

    _LOG_NAME: str = "jam"

    def __init__(
        self,
        log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        | str = "INFO",
    ):
        """Initialize the logger."""
        self.log_level = log_level

    @abstractmethod
    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log an informational message."""
        raise NotImplementedError

    @abstractmethod
    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log an error message.

        Args:
            message (str): Error message
            *args: Format arguments
            **kwargs: Logging kwargs (e.g. ``exc_info``)
        """
        raise NotImplementedError

    @abstractmethod
    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a warning message.

        Args:
            message (str): Warning message
            *args: Format arguments
            **kwargs: Logging kwargs (e.g. ``exc_info``)
        """
        raise NotImplementedError

    @abstractmethod
    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a debug message."""
        raise NotImplementedError


class JamLogger(BaseLogger):
    """Default jam logger, use stdlib logging."""

    _LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    def __init__(
        self,
        log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        | str = "INFO",
    ):
        """Initialize the logger."""
        if log_level not in self._LOG_LEVELS:
            log_level = "INFO"
        super().__init__(log_level)
        self.logger = logging.getLogger(self._LOG_NAME)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            self.logger.addHandler(logging.NullHandler())

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log an informational message."""
        self.logger.info(message, *args, **kwargs)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log an error message.

        Args:
            message (str): Error message
            *args: Format arguments
            **kwargs: Logging kwargs (e.g. ``exc_info``)
        """
        self.logger.error(message, *args, **kwargs)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a warning message.

        Args:
            message (str): Warning message
            *args: Format arguments
            **kwargs: Logging kwargs (e.g. ``exc_info``)
        """
        self.logger.warning(message, *args, **kwargs)

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a debug message."""
        self.logger.debug(message, *args, **kwargs)

    def __str__(self) -> str:
        """Return a string representation of the logger."""
        return f"JamLogger({self.logger.name})"

    def __repr__(self) -> str:
        """Return a string representation of the logger."""
        return f"JamLogger({self.logger.name})"


logger = JamLogger(os.getenv("JAM_LOG_LEVEL", "INFO").upper())
