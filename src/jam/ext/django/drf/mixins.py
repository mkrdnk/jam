# -*- coding: utf-8 -*-

"""View configuration helpers for Jam DRF permissions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from django.core.exceptions import ImproperlyConfigured


def _resolve_permissions(
    configured: Any,
    request: Any,
    view: Any,
    setting_name: str,
) -> tuple[str, ...]:
    """Resolve a view's action or method permission configuration."""
    value = configured
    if isinstance(value, Mapping):
        action = getattr(view, "action", None)
        value = value.get(action, value.get(request.method))
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, bytes):
        if all(isinstance(permission, str) for permission in value):
            return tuple(value)
    raise ImproperlyConfigured(
        f"{setting_name} must be a permission string, a sequence of strings, "
        "or a mapping of actions/methods to either."
    )


class JamPermissionMixin:
    """Provide declarative Jam permission mappings for DRF views."""

    jam_permissions: Any = None
    jam_object_permissions: Any = None

    def get_jam_permissions(self, request: Any) -> tuple[str, ...]:
        """Return request-level permissions for the current action or method."""
        return _resolve_permissions(
            self.jam_permissions,
            request,
            self,
            "jam_permissions",
        )

    def get_jam_object_permissions(
        self,
        request: Any,
        obj: Any,
    ) -> tuple[str, ...]:
        """Return object-level permissions for the current action or method."""
        return _resolve_permissions(
            self.jam_object_permissions,
            request,
            self,
            "jam_object_permissions",
        )
