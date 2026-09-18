# -*- coding: utf-8 -*-

"""Django authorization backend backed by Jam policies."""

from typing import Any

from django.contrib.auth.backends import BaseBackend

from jam.authz import Principal
from jam.ext.django.context import context_for, principal_context
from jam.ext.django.runtime import get_jam


class JamBackend(BaseBackend):
    """Answer Django permission checks through the configured Jam instance."""

    def has_perm(
        self,
        user_obj: Any,
        perm: str,
        obj: Any = None,
    ) -> bool:
        """Map Django's permission API to ``Jam.authorize``."""
        principal = principal_context.get()
        if principal is None or principal.subject != user_obj:
            principal = Principal(
                subject=user_obj,
                claims={},
                token_type="django",
            )
        return get_jam().authorize(principal, perm, context_for(obj))
