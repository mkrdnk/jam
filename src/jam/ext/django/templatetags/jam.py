# -*- coding: utf-8 -*-

"""Template support for object-level Django permission checks."""

from typing import Any

from django import template
from django.contrib.auth.models import AnonymousUser


register = template.Library()


@register.simple_tag(takes_context=True)
def jam_has_perm(
    context: template.Context,
    permission: str,
    obj: Any,
) -> bool:
    """Return whether the current user has a permission for ``obj``."""
    user = context.get("user", AnonymousUser())
    has_perm = getattr(user, "has_perm", None)
    return bool(has_perm is not None and has_perm(permission, obj))
