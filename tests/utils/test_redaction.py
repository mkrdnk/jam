# -*- coding: utf-8 -*-

import logging

import pytest

from jam.__defaults__ import defaults
from jam.utils.redaction import SensitiveDataFilter


def _record(message: str) -> logging.LogRecord:
    """Create a plain text LogRecord for the given message."""
    return logging.LogRecord(
        name="jam",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


class TestSensitiveDataFilter:
    """Test sensitive data redaction filter."""

    def test_default_redaction_enabled(self):
        """Filter redacts by default (opposite of defaults.DEBUG)."""
        f = SensitiveDataFilter()
        assert f.redact is not defaults.DEBUG

    def test_redact_false_leaves_message(self):
        """redact=False must not touch the message."""
        f = SensitiveDataFilter(redact=False)
        message = "token=abc123"
        record = _record(message)
        assert f.filter(record) is True
        assert record.getMessage() == message

    def test_redact_true(self):
        """redact=True forces redaction."""
        f = SensitiveDataFilter(redact=True)
        record = _record("token=abc123")
        assert f.filter(record) is True
        assert record.getMessage() == "[REDACTED]"

    def test_filter_never_drops_records(self):
        """filter() always returns True even for non-sensitive messages."""
        f = SensitiveDataFilter(redact=True)
        record = _record("all clear")
        assert f.filter(record) is True
        assert record.getMessage() == "all clear"

    def test_jwt_redaction(self):
        """A three-segment JWT is redacted."""
        f = SensitiveDataFilter(redact=True)
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        record = _record(f"Signed token: {token}")
        f.filter(record)
        assert "[REDACTED]" in record.getMessage()
        assert token not in record.getMessage()

    def test_jwe_redaction(self):
        """A five-segment JWE is redacted."""
        f = SensitiveDataFilter(redact=True)
        token = (
            "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
            ".90u7mWFxBNY0RnpC7xHj2g"
            ".6YlReVRKwlHryKc3xn3Wtw"
            ".ciphertext_bytes_here"
            ".tag_bytes_here"
        )
        record = _record(f"Encrypted: {token}")
        f.filter(record)
        assert "[REDACTED]" in record.getMessage()
        assert token not in record.getMessage()

    def test_paseto_redaction(self):
        """A PASETO token is redacted."""
        f = SensitiveDataFilter(redact=True)
        token = "v2.local.1234567890abcdefghijklmnopqrstuvwxyz-0123456789abcdef"
        record = _record(f"PASETO: {token}")
        f.filter(record)
        assert "[REDACTED]" in record.getMessage()
        assert token not in record.getMessage()

    def test_pem_private_key_redaction(self):
        """A PEM-encoded private key block is redacted."""
        f = SensitiveDataFilter(redact=True)
        key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0gFj\n"
            "-----END RSA PRIVATE KEY-----"
        )
        record = _record(f"Key:\n{key}")
        f.filter(record)
        assert "BEGIN RSA PRIVATE KEY" not in record.getMessage()
        assert "MIIEowIBAAKCAQEA0gFj" not in record.getMessage()
        assert "[REDACTED]" in record.getMessage()

    def test_key_value_secret_redaction(self):
        """key=value secrets are redacted."""
        f = SensitiveDataFilter(redact=True)
        record = _record("client_secret=sup3r_secret_value token=abc123")
        f.filter(record)
        assert "sup3r_secret_value" not in record.getMessage()
        assert "abc123" not in record.getMessage()

    def test_password_redaction(self):
        """password=value is redacted."""
        f = SensitiveDataFilter(redact=True)
        record = _record('password="hunter2"')
        f.filter(record)
        assert "hunter2" not in record.getMessage()

    def test_lazy_args_redaction(self):
        """%s-style args are folded into the message before redaction."""
        f = SensitiveDataFilter(redact=True)
        token = "v3.public.some-base64-payload.signaturebytes"
        record = logging.LogRecord(
            name="jam",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Token: %s",
            args=(token,),
            exc_info=None,
        )
        f.filter(record)
        assert "[REDACTED]" in record.getMessage()
        assert token not in record.getMessage()

    def test_installed_on_jam_logger(self):
        """The 'jam' logger has the filter attached."""
        jam_logger = logging.getLogger("jam")
        assert any(
            isinstance(f, SensitiveDataFilter)
            for f in jam_logger.filters
        )

    def test_child_loggers_covered(self):
        """The filter propagates to child loggers of 'jam'."""
        child = logging.getLogger("jam.jose.jwt")
        filters = []
        logger = child
        while logger is not None:
            filters.extend(logger.filters)
            logger = logger.parent
        assert any(isinstance(f, SensitiveDataFilter) for f in filters)
