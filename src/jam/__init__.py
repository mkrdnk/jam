# -*- coding: utf-8 -*-

"""JAM - Universal auth* library.

Source code: https://github.com/mkrdnk/jam
Documentation: https://jam.makridenko.ru
"""

import logging

from jam.__base__ import BaseJam
from jam.authz import (
    AuthorizationContext,
    BasePolicy,
    Policy,
    Principal,
)
from jam.instance import Jam
from jam.subject import BaseSubject
from jam.utils.redaction import SensitiveDataFilter


logging.getLogger("jam").addHandler(logging.NullHandler())
logging.getLogger("jam").addFilter(SensitiveDataFilter())


__version__ = "4.0.0b4"
__all__ = [
    "Jam",
    "BaseJam",
    "BaseSubject",
    "BasePolicy",
    "Policy",
    "Principal",
    "AuthorizationContext",
    "SensitiveDataFilter",
]
