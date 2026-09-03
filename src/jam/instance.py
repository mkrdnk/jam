# -*- coding: utf-8 -*-

import re
import time
from typing import Any

from jam.__base__ import BaseJam
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
        via: str | None = None,
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
            via (str | None): Token type: "jwt", "paseto", "session" or None
                for auto-detect (jwt first, then paseto).
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
        if isinstance(subject, dict):
            subject_id = subject.get("id")
            payload: dict[str, Any] = dict(subject)
        else:
            subject_id = subject.id
            payload = subject.to_dict()

        payload.update(claims)
        payload.pop("id", None)
        for registered_claim in ("exp", "iss", "aud", "nbf", "jti"):
            payload.pop(registered_claim, None)
        if subject_id is not None:
            payload["sub"] = subject_id
        if permissions is not None:
            payload["permissions"] = list(dict.fromkeys(permissions))
        credential_permissions = payload.get("permissions")
        if credential_permissions is not None and (
            not isinstance(credential_permissions, list)
            or not all(
                isinstance(permission, str) and permission
                for permission in credential_permissions
            )
        ):
            raise JamConfigurationError(
                message="Permissions must be a list of non-empty strings.",
                error_code="configuration.authz.invalid_permissions",
            )
        if via is None:
            if self.jwt is not None:
                return self.jwt.encode(
                    payload=payload,
                    exp=exp,
                    iss=iss,
                    aud=aud,
                    nbf=nbf,
                    jti=jti,
                )
            if self.paseto is not None:
                return self.__issue_paseto(payload, exp, iss, aud, nbf, jti)
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
                return self.__issue_paseto(payload, exp, iss, aud, nbf, jti)
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

    def authenticate(
        self, token: str, via: str | None = None
    ) -> Principal[Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (str | None): Token type: "jwt", "paseto", "session" or None
                for auto-detect.

        Returns:
            Principal: Authenticated subject and credential claims.

        Raises:
            JamConfigurationError: If no matching module is configured.
            JamSessionNotFound: If a session does not exist.
        """
        if via is None:
            via = self.__detect(token)

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

    @staticmethod
    def __detect(token: str) -> str:
        """Detect the token type from its format.

        Args:
            token (str): Token or session ID.

        Returns:
            str: "paseto", "jwe", "jwt" or "session".
        """
        if re.match(r"^v[1-4]\.(local|public)\.", token):
            return "paseto"
        if token.count(".") == 4:
            return "jwe"
        if token.count(".") == 2:
            return "jwt"
        return "session"

    def __issue_paseto(
        self,
        payload: dict[str, Any],
        exp: int | None,
        iss: str | None,
        aud: str | None,
        nbf: int | None,
        jti: str | None,
    ) -> str:
        """Encode a payload with the configured PASETO module.

        Args:
            payload (dict[str, Any]): Payload.
            exp (int | None): Expiration in seconds.
            iss (str | None): Issuer.
            aud (str | None): Audience.
            nbf (int | None): Not-before in seconds.
            jti (str | None): Token ID.

        Returns:
            str: PASETO token.
        """
        data = dict(payload)
        if exp is not None:
            data["exp"] = int(time.time()) + exp
        if nbf is not None:
            data["nbf"] = int(time.time()) + nbf
        if iss is not None:
            data["iss"] = iss
        if aud is not None:
            data["aud"] = aud
        if jti is not None:
            data["jti"] = jti
        return self.paseto.encode(payload=data)
