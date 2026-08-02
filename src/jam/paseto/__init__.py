# -*- coding: utf-8 -*-

"""PASETO auth tokens."""

from typing import Any

from .__base__ import BasePASETO
from .v1 import PASETOv1
from .v2 import PASETOv2
from .v3 import PASETOv3
from .v4 import PASETOv4


REGISTRY: dict[str, type[BasePASETO]] = {
    "v1": PASETOv1,
    "v2": PASETOv2,
    "v3": PASETOv3,
    "v4": PASETOv4,
}


__all__ = [
    "PASETOv1",
    "PASETOv2",
    "PASETOv3",
    "PASETOv4",
    "BasePASETO",
    "REGISTRY",
]
