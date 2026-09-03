# -*- coding: utf-8 -*-

from typing import Any

from jam.aio.__base__ import BaseAsyncJam
from jam.authz import AuthorizationContext, Principal
from jam.exceptions import (
    JamConfigurationError,
    JamJWSVerificationError,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamSessionNotFound,
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
        return self._policy.check(principal, permission, context)

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
        payload = self._prepare_payload(subject, permissions, claims)

        if via is None:
            if self.jwt is not None:
                return await self._issue_jwt(payload, exp, iss, aud, nbf, jti)
            if self.paseto is not None:
                return self._issue_paseto(
                    payload,
                    exp,
                    iss,
                    aud,
                    nbf,
                    jti,
                )
            raise JamConfigurationError(
                message=(
                    "Cannot issue a token: no jwt or paseto module configured. "
                    "Pass 'via' explicitly or configure a module."
                ),
                error_code="configuration.issue_not_configured",
            )

        match via:
            case "jwt":
                if self.jwt is None:
                    raise JamConfigurationError(
                        message="JWT module is not configured.",
                        error_code="configuration.jwt.not_configured",
                    )
                return await self._issue_jwt(payload, exp, iss, aud, nbf, jti)
            case "paseto":
                if self.paseto is None:
                    raise JamConfigurationError(
                        message="PASETO module is not configured.",
                        error_code="configuration.paseto.not_configured",
                    )
                return self._issue_paseto(
                    payload,
                    exp,
                    iss,
                    aud,
                    nbf,
                    jti,
                )
            case "session":
                if self.session is None:
                    raise JamConfigurationError(
                        message="Session module is not configured.",
                        error_code="configuration.session.not_configured",
                    )
                session_key = (
                    (self.config or {})
                    .get("session", {})
                    .get("session_key", "auth")
                )
                return await self.session.create(session_key, payload)
            case _:
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, paseto, session",
                    error_code="configuration.issue_unknown_via",
                )

    async def authenticate(
        self,
        token: str,
        via: str | None = None,
    ) -> Principal[Any]:
        """Authenticate a token or session and return its principal."""
        if via is None:
            via = self._detect_token_type(token)

        match via:
            case "jwt":
                if self.jwt is None:
                    raise JamConfigurationError(
                        message="JWT module is not configured.",
                        error_code="configuration.jwt.not_configured",
                    )
                if self._jwt_list is not None:
                    listed = await self._jwt_list.check(token)
                    if self._jwt_list.__list_type__ == "white" and not listed:
                        raise JamJWTNotInWhiteList
                    if self._jwt_list.__list_type__ == "black" and listed:
                        raise JamJWTInBlackList
                payload = self.jwt.decode(token, check_list=False)["payload"]
            case "jwe":
                if self.jwt is None or self.jwt.jwe is None:
                    raise JamConfigurationError(
                        message="JWE module is not configured.",
                        error_code="configuration.jwe.not_configured",
                    )
                decrypted = self.jwt.decrypt(token)
                if not isinstance(decrypted, dict):
                    raise JamJWSVerificationError(
                        message="JWE payload is not a serialized object.",
                    )
                payload = decrypted
            case "paseto":
                if self.paseto is None:
                    raise JamConfigurationError(
                        message="PASETO module is not configured.",
                        error_code="configuration.paseto.not_configured",
                    )
                payload, _footer = self.paseto.decode(token)
            case "session":
                if self.session is None:
                    raise JamConfigurationError(
                        message="Session module is not configured.",
                        error_code="configuration.session.not_configured",
                    )
                data = await self.session.get(token)
                if data is None:
                    raise JamSessionNotFound(details={"session_id": token})
                payload = data
            case _:
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, paseto, session",
                    error_code="configuration.authenticate_unknown_via",
                )

        return Principal(
            subject=self._subject_from_payload(payload),
            claims=dict(payload),
            token_type=via,
        )

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
        if (
            self._jwt_list is not None
            and self._jwt_list.__list_type__ == "white"
        ):
            await self._jwt_list.add(token)
        return token

    async def aclose(self) -> None:
        """Close I/O clients owned by this instance."""
        modules = [
            self.session,
            self._jwt_list,
            *((self.oauth2 or {}).values()),
        ]
        for module in modules:
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
