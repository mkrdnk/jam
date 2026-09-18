# -*- coding: utf-8 -*-

"""Django class-based-view helpers unavailable in Django itself."""

from collections.abc import Iterable
from typing import Any

from django.contrib.auth.mixins import AccessMixin
from django.core.exceptions import ImproperlyConfigured, PermissionDenied


class ObjectPermissionRequiredMixin(AccessMixin):
    """Require Django permissions against an object returned by this view."""

    permission_required: str | Iterable[str] | None = None

    def get_permission_required(self) -> tuple[str, ...]:
        """Return configured permissions using Django's mixin semantics."""
        if self.permission_required is None:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} is missing permission_required."
            )
        if isinstance(self.permission_required, str):
            return (self.permission_required,)
        return tuple(self.permission_required)

    def get_permission_object(self) -> Any:
        """Return the object passed to ``user.has_perm``."""
        raise NotImplementedError(
            "ObjectPermissionRequiredMixin requires get_permission_object()."
        )

    def has_permission(self) -> bool:
        """Check every requested permission through Django's user API."""
        user = self.request.user
        obj = self.get_permission_object()
        return all(
            user.has_perm(permission, obj)
            for permission in self.get_permission_required()
        )

    def dispatch(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        """Deny access with Django's normal permission exception."""
        self.request = request
        self.args = args
        self.kwargs = kwargs
        if not self.has_permission():
            if self.raise_exception or request.user.is_authenticated:
                raise PermissionDenied(self.get_permission_denied_message())
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)
