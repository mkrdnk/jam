"""Macaroon verification errors."""

from .base import JamValidationError


class MacaroonError(JamValidationError):
    """Base error for macaroon validation."""

    default_code = "macaroon.validation"


class SerializationError(MacaroonError):
    """Malformed or oversized macaroon transport."""

    default_code = "macaroon.serialization"


class VerificationError(MacaroonError):
    """Invalid signature, discharge graph, or unsatisfied predicate."""

    default_code = "macaroon.verification"


class InvalidCaveatError(VerificationError):
    """Unknown or malformed structured caveat."""

    default_code = "macaroon.invalid_caveat"
