# -*- coding: utf-8 -*-

"""Jam (Jam Auth Module) - A universal auth* framework that provides popular
auth mechanisms strictly according to the specification.

Source code: https://github.com/mkrdnk/jam
Documentation: https://jam.makridenko.com
"""

import logging

from jam.__base__ import BaseJam
from jam.authz import (
    AuthorizationConstraint,
    AuthorizationContext,
    BasePolicy,
    ConditionConstraint,
    PermissionConstraint,
    Policy,
    Principal,
)
from jam.instance import Jam
from jam.macaroons import Caveat, CaveatRegistry, Macaroon
from jam.subject import BaseSubject
from jam.utils.redaction import SensitiveDataFilter


logging.getLogger("jam").addHandler(logging.NullHandler())
logging.getLogger("jam").addFilter(SensitiveDataFilter())


__version__ = "4.2.0b1"
__all__ = [
    "Jam",
    "BaseJam",
    "BaseSubject",
    "BasePolicy",
    "Policy",
    "Principal",
    "AuthorizationConstraint",
    "AuthorizationContext",
    "ConditionConstraint",
    "PermissionConstraint",
    "Caveat",
    "CaveatRegistry",
    "Macaroon",
    "SensitiveDataFilter",
]
