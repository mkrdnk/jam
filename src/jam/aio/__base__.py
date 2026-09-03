# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any

from jam.__base__ import _JamCore
from jam.authz import AuthorizationContext, Principal
from jam.subject import BaseSubject


class BaseAsyncJam(_JamCore, ABC):
    """Base asynchronous Jam instance.

    Only operations which can cross an I/O boundary are asynchronous.
    Cryptographic modules, OTP and authorization policies remain synchronous.
    """

    _async = True

    @abstractmethod
    def authorize(
        self,
        principal: Principal[Any] | BaseSubject | dict[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Check whether a principal may perform a permission."""
        raise NotImplementedError

    @abstractmethod
    async def issue(
        self,
        subject: BaseSubject | dict[str, Any],
        via: str | None = None,
        exp: int | None = None,
        iss: str | None = None,
        aud: str | None = None,
        nbf: int | None = None,
        jti: str | None = None,
        permissions: list[str] | None = None,
        **claims: Any,
    ) -> str:
        """Issue a token or create a session."""
        raise NotImplementedError

    @abstractmethod
    async def authenticate(
        self,
        token: str,
        via: str | None = None,
    ) -> Principal[Any]:
        """Authenticate a token or session."""
        raise NotImplementedError


__all__ = ["BaseAsyncJam"]
