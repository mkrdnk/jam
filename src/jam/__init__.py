# -*- coding: utf-8 -*-

"""JAM - Universal auth* library.

Source code: https://github.com/mkrdnk/jam
Documentation: https://jam.makridenko.ru
"""

from jam.__base__ import BaseJam
from jam.authz import BasePolicy, Policy
from jam.instance import Jam
from jam.subject import BaseSubject


__version__ = "3.3.0.post0"
__all__ = ["Jam", "BaseJam"]
