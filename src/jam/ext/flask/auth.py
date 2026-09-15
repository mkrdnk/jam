# -*- coding: utf-8 -*-

from __future__ import annotations

from collections.abc import Callable, Sequence
from functools import wraps
from typing import Any, ParamSpec, TypeVar, cast

from flask import Flask, Response, abort, current_app, g, request
from werkzeug.local import LocalProxy

from jam import Jam
from jam.authz import Principal
from jam.ext._base import DEFAULT_SOURCES, Authenticator, CredentialSource


P = ParamSpec("P")
R = TypeVar("R")


def _get_principal() -> Principal[Any] | None:
    return getattr(g, "principal", None)


current_principal = cast(
    "Principal[Any] | None",
    LocalProxy(_get_principal),
)


class JamAuth:
    """Flask extension providing authentication and permission decorators."""

    def __init__(
        self,
        app: Flask | None = None,
        *,
        jam: Jam | None = None,
        sources: Sequence[CredentialSource] = DEFAULT_SOURCES,
        via: str | None = None,
    ) -> None:
        """Initialize now or defer registration for an app factory."""
        self.jam = jam
        self.sources = tuple(sources)
        self.via = via
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask, *, jam: Jam | None = None) -> None:
        """Register the extension on a Flask application factory."""
        instance = jam or self.jam
        if instance is None:
            raise ValueError("A Jam instance is required.")
        self.jam = instance
        self.authenticator = Authenticator(
            instance,
            sources=self.sources,
            via=self.via,
        )
        app.extensions["jam"] = instance
        app.extensions["jam_auth"] = self
        app.before_request(self._authenticate_request)

    def _authenticate_request(self) -> None:
        result = self.authenticator.authenticate_request(
            headers=dict(request.headers),
            cookies=dict(request.cookies),
            query=dict(request.args),
        )
        g.jam = self.jam
        g.principal = result.principal
        g.authentication = result

    def login_required(self, view: Callable[P, R]) -> Callable[P, R]:
        """Require an authenticated principal for a view."""

        @wraps(view)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            if _get_principal() is None:
                abort(
                    Response(
                        "Authentication required.",
                        401,
                        {"WWW-Authenticate": "Bearer"},
                    )
                )
            return view(*args, **kwargs)

        return wrapped

    def permission_required(
        self,
        permission: str,
        *,
        context: Callable[[], Any] | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Require authentication and one Jam permission for a view."""

        def decorator(view: Callable[P, R]) -> Callable[P, R]:
            @self.login_required
            @wraps(view)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                principal = _get_principal()
                jam = self.jam
                if jam is None:
                    raise RuntimeError("JamAuth is not registered on an app.")
                if principal is None or not jam.authorize(
                    principal,
                    permission,
                    context() if context is not None else None,
                ):
                    abort(403, "Permission denied.")
                return view(*args, **kwargs)

            return wrapped

        return decorator


def get_jam() -> Jam:
    """Return the Jam instance registered on the current Flask app."""
    return current_app.extensions["jam"]
