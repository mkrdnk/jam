# -*- coding: utf-8 -*-

"""Django-native authentication and authorization integration."""

from importlib import import_module
from typing import TYPE_CHECKING, Any


__all__ = [
    "JamBackend",
    "JamMiddleware",
    "ObjectPermissionRequiredMixin",
    "get_jam",
]


if TYPE_CHECKING:
    from jam.ext.django.backends import JamBackend
    from jam.ext.django.middleware import JamMiddleware
    from jam.ext.django.mixins import ObjectPermissionRequiredMixin
    from jam.ext.django.runtime import get_jam


_PUBLIC_MODULES = {
    "JamBackend": "jam.ext.django.backends",
    "JamMiddleware": "jam.ext.django.middleware",
    "ObjectPermissionRequiredMixin": "jam.ext.django.mixins",
    "get_jam": "jam.ext.django.runtime",
}


def __getattr__(name: str) -> Any:
    """Import public Django integration objects only after app setup."""
    module_name = _PUBLIC_MODULES.get(name)
    if module_name is None:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        )
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
