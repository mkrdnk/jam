# -*- coding: utf-8 -*-

"""Macaroon implementation."""

from jam.exceptions.macaroons import (
    InvalidCaveatError,
    MacaroonError,
    SerializationError,
    VerificationError,
)

from .__base__ import BaseMacaroon
from .config import create_instance
from .core import (
    Caveat,
    FirstPartyCaveat,
    Limits,
    Macaroon,
    ThirdPartyCaveat,
    VerificationResult,
)
from .profile import CaveatRegistry, MacaroonModule

__all__ = [
    "BaseMacaroon", "Caveat", "CaveatRegistry", "FirstPartyCaveat",
    "InvalidCaveatError", "Limits", "Macaroon", "MacaroonError",
    "MacaroonModule", "SerializationError", "ThirdPartyCaveat",
    "VerificationError", "VerificationResult", "create_instance",
]
