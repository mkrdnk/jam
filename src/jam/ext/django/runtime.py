# -*- coding: utf-8 -*-

"""Process-wide Jam instance management."""

from functools import cache
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed

from jam import Jam
from jam.aio import AsyncJam


@cache
def get_jam() -> Jam:
    """Return the process-wide Jam instance configured by ``JAM_CONFIG``."""
    if not hasattr(settings, "JAM_CONFIG"):
        raise ImproperlyConfigured(
            "JAM_CONFIG must be defined to use the Jam Django integration."
        )
    config: Any = settings.JAM_CONFIG
    if not isinstance(config, dict):
        raise ImproperlyConfigured(
            "JAM_CONFIG must be a Jam configuration dict."
        )
    return Jam(config=config)


@cache
def get_async_jam() -> AsyncJam:
    """Return the async Jam instance backed by the same Django setting."""
    if not hasattr(settings, "JAM_CONFIG"):
        raise ImproperlyConfigured(
            "JAM_CONFIG must be defined to use the Jam Django integration."
        )
    config: Any = settings.JAM_CONFIG
    if not isinstance(config, dict):
        raise ImproperlyConfigured(
            "JAM_CONFIG must be a Jam configuration dict."
        )
    return AsyncJam(config=config)


def _clear_jam_cache(**kwargs: Any) -> None:
    """Clear the cached instance after a Django settings override."""
    if kwargs.get("setting") == "JAM_CONFIG":
        get_jam.cache_clear()
        get_async_jam.cache_clear()


setting_changed.connect(_clear_jam_cache)
