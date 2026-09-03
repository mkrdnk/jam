# -*- coding: utf-8 -*-

"""FastAPI authentication and authorization dependencies."""

from collections.abc import Awaitable, Callable, Sequence
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from jam import Jam
from jam.authz import Principal
from jam.ext._base import DEFAULT_SOURCES, Authenticator, CredentialSource


_bearer = HTTPBearer(auto_error=False)
BearerCredential = Annotated[
    HTTPAuthorizationCredentials | None,
    Security(_bearer),
]


class JamAuth:
    """Reusable FastAPI dependency backed by a configured Jam instance."""

    def __init__(
        self,
        jam: Jam,
        *,
        sources: Sequence[CredentialSource] = DEFAULT_SOURCES,
        via: str | None = None,
    ) -> None:
        self.jam = jam
        self.authenticator = Authenticator(jam, sources=sources, via=via)

    async def optional(
        self,
        request: Request,
        credential: BearerCredential = None,
    ) -> Principal[Any] | None:
        """Return a principal or ``None`` when no valid credential exists."""
        headers = dict(request.headers)
        if credential is not None:
            headers["Authorization"] = (
                f"{credential.scheme} {credential.credentials}"
            )
        result = await run_in_threadpool(
            self.authenticator.authenticate_request,
            headers=headers,
            cookies=dict(request.cookies),
            query=dict(request.query_params),
        )
        request.state.jam = self.jam
        request.state.principal = result.principal
        request.state.authentication = result
        return result.principal

    async def __call__(
        self,
        request: Request,
        credential: BearerCredential = None,
    ) -> Principal[Any]:
        """Require and return the authenticated principal."""
        principal = await self.optional(request, credential)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return principal

    def require(
        self,
        permission: str,
        *,
        context: Callable[[Request, Principal[Any]], Any] | None = None,
    ) -> Callable[..., Awaitable[Principal[Any]]]:
        """Build a dependency requiring one Jam permission."""

        async def dependency(
            request: Request,
            principal: Annotated[Principal[Any], Depends(self)],
        ) -> Principal[Any]:
            authz_context = (
                context(request, principal) if context is not None else None
            )
            allowed = await run_in_threadpool(
                self.jam.authorize,
                principal,
                permission,
                authz_context,
            )
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Permission denied.",
                )
            return principal

        return dependency


__all__ = ["CredentialSource", "JamAuth"]
