# -*- coding: utf-8 -*-

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from typing import Any

from jam.__core__ import JamAuthType, _JamCore
from jam.authz import (
    AuthorizationContext,
    Principal,
)
from jam.exceptions import JamConfigurationError
from jam.subject import BaseSubject


logger = logging.getLogger(__name__)


class BaseJam(_JamCore, ABC):
    """Base synchronous Jam instance."""

    @abstractmethod
    def authorize(
        self,
        principal: Principal[Any] | BaseSubject | dict[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Check whether a subject is allowed to perform a permission.

        Args:
            principal: Authenticated principal, subject or subject mapping.
            permission (str): Permission name.
            context: Dynamic authorization context.

        Returns:
            bool: True if allowed, False otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def issue(
        self,
        subject: BaseSubject | dict[str, Any],
        via: JamAuthType,
        exp: int | None = None,
        iss: str | None = None,
        aud: str | None = None,
        nbf: int | None = None,
        jti: str | None = None,
        permissions: list[str] | None = None,
        **claims: Any,
    ) -> str:
        """Issue a token or session for a subject.

        Args:
            subject (BaseSubject | dict[str, Any]): Subject instance.
            via (JamAuthType): Token type: "jwt", "paseto" or "session".
            exp (int | None): Expiration in seconds.
            iss (str | None): Issuer.
            aud (str | None): Audience.
            nbf (int | None): Not-before in seconds.
            jti (str | None): Token ID.
            permissions: Permissions granted to this credential.
            **claims: Extra payload claims.

        Returns:
            str: Issued token or session ID.
        """
        raise NotImplementedError

    @abstractmethod
    def authenticate(self, token: str, via: JamAuthType) -> Principal[Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (JamAuthType): Token type: "jwt", "paseto" or "session".

        Returns:
            Principal: Authenticated subject and credential claims.
        """
        raise NotImplementedError

    def emit(self, event: str, **kwargs: Any) -> dict[str, Any]:
        """Emit event.

        Args:
            event (str): Event name,
            **kwargs: Event data

        Returns:
            dict[str, Any]: Updated event data.
        """
        from jam.__defaults__ import defaults

        if not defaults.ENABLE_PLUGINS:
            raise JamConfigurationError(
                message="Plugins are disabled."
                "To enable them, use JAM_ENABLE_PLUGINS=1."
                "Please note! Plugins are an experimental feature!",
                error_code="plugins.disable",
                details={
                    "plugins": self._plugins,
                    "plugins_status": defaults.ENABLE_PLUGINS,
                },
            )
        logging.warning("Plugins are an experemental feature!")
        for plugin in self._plugins:
            handler = getattr(plugin, f"on_{event}", None)

            if handler:
                try:
                    result = handler(**kwargs)
                    if isinstance(result, dict):
                        kwargs.update(result)

                except Exception as e:
                    logger.error("Plugin: %s | error: %s", plugin.name, e)

        return kwargs
