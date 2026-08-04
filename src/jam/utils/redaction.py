# -*- coding: utf-8 -*-

"""Logging helpers: sensitive data redaction."""

import logging
import re

from jam.__defaults__ import defaults


_REDACTED = "[REDACTED]"

_TOKEN_RE = (
    r"[A-Za-z0-9_-]{6,}\."
    r"[A-Za-z0-9_-]{6,}\."
    r"[A-Za-z0-9_-]{6,}\."
    r"[A-Za-z0-9_-]{6,}\."
    r"[A-Za-z0-9_-]+"
)
_JWE_RE = re.compile(_TOKEN_RE)
_JWT_RE = re.compile(r"[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+")
_PASETO_RE = re.compile(
    r"v[1-4]\.(?:local|public)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?"
)
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_SECRET_RE = re.compile(
    r"\b(?:secret|secret_key|client_secret|password|passwd|passphrase|"
    r"token|refresh_token|access_token|api[_-]?key|private_key)\b"
    r"\s*[:=]\s*[\"']?[^\s\"',}]+"
)

_PATTERNS = [
    _JWE_RE,
    _JWT_RE,
    _PASETO_RE,
    _PEM_RE,
    _SECRET_RE,
]


class SensitiveDataFilter(logging.Filter):
    """Redact tokens and secrets from log records.

    Enabled by default. Set ``JAM_DEBUG=True`` (see ``jam.__defaults__``)
    to disable redaction and see full values while developing.

    Args:
        redact (bool | None): Force redaction on/off. Defaults to the
            opposite of ``defaults.DEBUG``.
    """

    def __init__(self, redact: bool | None = None) -> None:
        """Initialize the filter."""
        super().__init__()
        self.redact = not defaults.DEBUG if redact is None else redact

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data in a log record.

        Args:
            record (logging.LogRecord): Log record to sanitize.

        Returns:
            bool: Always True, so the record is never dropped.
        """
        if not self.redact:
            return True
        try:
            message = record.getMessage()
        except Exception:
            return True
        for pattern in _PATTERNS:
            message = pattern.sub(_REDACTED, message)
        record.msg = message
        record.args = ()
        return True


__all__ = ["SensitiveDataFilter"]
