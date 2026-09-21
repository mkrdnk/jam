# -*- coding: utf-8 -*-

"""Build the data roots used by authorization comparisons."""

from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from typing import Any, cast

from jam.authz.__base__ import AuthorizationContext, Principal, Subject


def _condition_roots(
    principal: Principal[Any],
    context: AuthorizationContext,
    *,
    stored_attributes_only: bool = False,
) -> dict[str, Any]:
    return {
        "subject": (
            principal.subject
            if stored_attributes_only
            else _subject_data(principal.subject)
        ),
        "token": principal.claims,
        "context": {
            "time": context.now,
            "now": context.now,
            "resource": context.resource,
            "request": context.request,
            "attributes": context.attributes,
        },
    }


def _subject_data(subject: Subject) -> object:
    if isinstance(subject, Mapping):
        return subject
    if is_dataclass(subject):
        return asdict(cast(Any, subject))
    return subject
