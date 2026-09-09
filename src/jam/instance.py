# -*- coding: utf-8 -*-

from typing import Any

from jam.__base__ import BaseJam, JamAuthType
from jam.authz import AuthorizationContext, Principal
from jam.exceptions import (
    JamConfigurationError,
    JamJWSVerificationError,
    JamSessionNotFound,
)
from jam.subject import BaseSubject


class Jam(BaseJam):
    """Main instance."""

    def authorize(
        self,
        principal: Principal[Any] | BaseSubject | dict[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Check whether a subject is allowed to perform a permission.

        Uses the policy configured under ``[jam.authz]``. Deny by default.

        Args:
            principal: Authenticated principal, subject or subject mapping.
            permission (str): Permission name, e.g. ``"post:edit"``.
            context: Dynamic authorization context.

        Returns:
            bool: True if allowed, False otherwise.

        """
        return self._policy.check(principal, permission, context)

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
            subject (BaseSubject): Subject instance or dict with an "id".
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

        Raises:
            JamConfigurationError: If no matching module is configured.
        """
        payload = self._prepare_payload(subject, permissions, claims)
        match via:
            case "jwt":
                if self.jwt is None:
                    raise JamConfigurationError(
                        message="JWT module is not configured.",
                        error_code="configuration.jwt.not_configured",
                    )
                return self.jwt.encode(
                    payload=payload,
                    exp=exp,
                    iss=iss,
                    aud=aud,
                    nbf=nbf,
                    jti=jti,
                )
            case "paseto":
                if self.paseto is None:
                    raise JamConfigurationError(
                        message="PASETO module is not configured.",
                        error_code="configuration.paseto.not_configured",
                    )
                return self._issue_paseto(payload, exp, iss, aud, nbf, jti)
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
                return self.session.create(session_key, payload)
            case _:
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, paseto, session",
                    error_code="configuration.issue_unknown_via",
                )

    def authenticate(self, token: str, via: JamAuthType) -> Principal[Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (str | None): Token type: "jwt", "paseto" or "session".

        Returns:
            Principal: Authenticated subject and credential claims.

        Raises:
            JamConfigurationError: If no matching module is configured.
            JamSessionNotFound: If a session does not exist.
        """
        match via:
            case "jwt":
                if self.jwt is None:
                    raise JamConfigurationError(
                        message="JWT module is not configured.",
                        error_code="configuration.jwt.not_configured",
                    )
                payload = self.jwt.decode(token)["payload"]
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
                data = self.session.get(token)
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
