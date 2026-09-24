# -*- coding: utf-8 -*-

from collections.abc import Sequence
from typing import Any

from jam.__core__ import JamAuthType, JamIssueType
from jam.aio.__base__ import BaseAsyncJam
from jam.authz import AuthorizationContext, Principal
from jam.exceptions import (
    JamConfigurationError,
    JamSessionNotFound,
    JamTokenInDenyList,
    JamTokenNotInAllowList,
)
from jam.subject import BaseSubject


class AsyncJam(BaseAsyncJam):
    """Asynchronous Jam facade.

    Stateless modules remain synchronous. High-level credential operations
    are always awaitable because sessions and token registries may perform I/O.
    """

    def authorize(
        self,
        principal: Principal[Any] | BaseSubject | dict[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Check whether a principal may perform a permission."""
        return self._authorize(principal, permission, context)

    async def issue(
        self,
        subject: BaseSubject | dict[str, Any],
        via: JamIssueType,
        exp: int | None = None,
        iss: str | None = None,
        aud: str | None = None,
        nbf: int | None = None,
        jti: str | None = None,
        permissions: list[str] | None = None,
        **claims: Any,
    ) -> str:
        """Issue a token or create a session."""
        payload = self._prepare_payload(subject, permissions, claims)
        match via:
            case "macaroon":
                token = self.macaroon.issue(
                    payload,
                    exp=exp,
                    nbf=nbf,
                    iss=iss,
                    aud=aud,
                    jti=jti,
                )
                await self._register_allowlisted_token(
                    self._macaroon_list, token
                )
                return token
            case "jwt":
                return await self._issue_jwt(payload, exp, iss, aud, nbf, jti)
            case "paseto":
                token = self._issue_paseto(
                    payload,
                    exp,
                    iss,
                    aud,
                    nbf,
                    jti,
                )
                await self._register_allowlisted_token(self._paseto_list, token)
                return token
            case "saml":
                token = self._issue_saml(payload, exp, iss, aud, nbf, jti)
                await self._register_allowlisted_token(self._saml_list, token)
                return token
            case "session":
                session = self.session
                session_key = (
                    (self.config or {})
                    .get("session", {})
                    .get("session_key", "auth")
                )
                session_payload = self._prepare_session_payload(
                    payload,
                    exp,
                    iss,
                    aud,
                    nbf,
                    jti,
                )
                return await session.create(session_key, session_payload)
            case _:
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, paseto, session, macaroon, saml",
                    error_code="configuration.issue_unknown_via",
                )

    async def authenticate(
        self,
        token: str,
        via: JamAuthType,
        *,
        discharges: Sequence[str | bytes] | None = None,
    ) -> Principal[Any]:
        """Authenticate a token or session and return its principal."""
        constraints = ()
        match via:
            case "macaroon":
                await self._check_token_list(self._macaroon_list, token)
                payload, constraints = self.macaroon.authenticate(
                    token,
                    discharges=() if discharges is None else discharges,
                )
            case "jwt":
                await self._check_token_list(self._jwt_list, token)
                payload = self.jwt.decode(token, check_list=False)["payload"]
            case "jwe":
                payload = self._authenticate_jwe(token)
            case "paseto":
                await self._check_token_list(self._paseto_list, token)
                payload, _footer = self.paseto.decode(token)
            case "saml":
                await self._check_token_list(self._saml_list, token)
                payload = self._authenticate_saml(token)
            case "session":
                data = await self.session.get(token)
                if data is None:
                    raise JamSessionNotFound(details={"session_id": token})
                self._validate_session_payload(data)
                payload = data
            case _:
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, jwe, paseto, session, macaroon, saml",
                    error_code="configuration.authenticate_unknown_via",
                )

        return Principal(
            subject=self._subject_from_payload(payload),
            claims=dict(payload),
            token_type=via,
            constraints=constraints,
        )

    @staticmethod
    async def _register_allowlisted_token(token_list: Any, token: str) -> None:
        """Register an issued token when an async allowlist is configured."""
        if token_list is not None and token_list.__list_type__ == "white":
            await token_list.add(token)

    @staticmethod
    async def _check_token_list(token_list: Any, token: str) -> None:
        """Enforce an optional async token allowlist or denylist."""
        if token_list is None:
            return
        listed = await token_list.check(token)
        if token_list.__list_type__ == "white" and not listed:
            raise JamTokenNotInAllowList
        if token_list.__list_type__ == "black" and listed:
            raise JamTokenInDenyList

    async def _issue_jwt(
        self,
        payload: dict[str, Any],
        exp: int | None,
        iss: str | None,
        aud: str | None,
        nbf: int | None,
        jti: str | None,
    ) -> str:
        """Encode JWT and persist it when an async allowlist is configured."""
        token = self.jwt.encode(
            payload=payload,
            exp=exp,
            iss=iss,
            aud=aud,
            nbf=nbf,
            jti=jti,
        )
        await self._register_allowlisted_token(self._jwt_list, token)
        return token

    async def aclose(self) -> None:
        """Close I/O clients owned by this instance."""
        modules = [
            self._session,
            *self.lists.values(),
            self._jwt_list,
            self._paseto_list,
            self._macaroon_list,
            self._saml_list,
            *((self._oauth2 or {}).values()),
        ]
        closed: set[int] = set()
        for module in modules:
            if module is None or id(module) in closed:
                continue
            closed.add(id(module))
            close = getattr(module, "aclose", None)
            if close is not None:
                await close()

    async def __aenter__(self) -> "AsyncJam":
        """Enter an asynchronous resource context."""
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """Close owned resources when leaving a context."""
        await self.aclose()


# Compatibility with the pre-4.0 import path.
Jam = AsyncJam

__all__ = ["AsyncJam", "Jam"]
