# -*- coding: utf-8 -*-

"""Jam-native DRF authorization permissions."""

from __future__ import annotations

from typing import Any

from rest_framework.permissions import BasePermission

from jam.authz import AuthorizationContext, Principal
from jam.ext.django.runtime import get_jam


class JamPermission(BasePermission):
    """Authorize configured DRF view permissions through Jam policies."""

    @staticmethod
    def _principal(request: Any) -> Principal[Any]:
        """Return token principal or adapt another DRF authenticated user."""
        auth = getattr(request, "auth", None)
        if isinstance(auth, Principal):
            return auth
        return Principal(
            subject=request.user,
            claims={},
            token_type="django",
        )

    def has_permission(self, request: Any, view: Any) -> bool:
        """Check all configured request-level Jam permissions."""
        resolver = getattr(view, "get_jam_permissions", None)
        if resolver is None:
            return True
        permissions = resolver(request)
        principal = self._principal(request)
        context = AuthorizationContext(request=request)
        return all(
            get_jam().authorize(principal, permission, context)
            for permission in permissions
        )

    def has_object_permission(
        self,
        request: Any,
        view: Any,
        obj: Any,
    ) -> bool:
        """Check all configured object-level Jam permissions."""
        resolver = getattr(view, "get_jam_object_permissions", None)
        if resolver is None:
            return True
        permissions = resolver(request, obj)
        principal = self._principal(request)
        context = AuthorizationContext(request=request, resource=obj)
        return all(
            get_jam().authorize(principal, permission, context)
            for permission in permissions
        )
