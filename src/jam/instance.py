# -*- coding: utf-8 -*-

import re
import time
from typing import Any

from jam.__base__ import BaseJam
from jam.exceptions import (
    JamConfigurationError,
    JamJWSVerificationError,
    JamSessionNotFound,
)
from jam.subject import BaseSubject


class Jam(BaseJam):
    """Main instance."""

    def authorize(self, subject: BaseSubject, permission: str) -> bool:
        """Check whether a subject is allowed to perform a permission.

        Uses the policy configured under ``[jam.authz]``. Deny by default.

        Args:
            subject (BaseSubject): Subject instance.
            permission (str): Permission name, e.g. ``"post:edit"``.

        Returns:
            bool: True if allowed, False otherwise.

        Raises:
            JamConfigurationError: If no authz policy is configured.
        """
        if self._policy is None:
            raise JamConfigurationError(
                message=(
                    "Authz policy is not configured. Add a [jam.authz] "
                    "section to your config."
                ),
                error_code="authz.not_configured",
            )
        return self._policy.check(subject, permission)

    def issue(
        self,
        subject: BaseSubject,
        via: str | None = None,
        exp: int | None = None,
        iss: str | None = None,
        aud: str | None = None,
        nbf: int | None = None,
        jti: str | None = None,
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

        if subject_id is not None:
            payload["sub"] = subject_id
        payload.update(claims)

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
                return self.__issue_paseto(payload, exp, iss, aud, jti)
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
                return self.__issue_paseto(payload, exp, iss, aud, jti)
            case "session":
                if self.session is None:
                    raise JamConfigurationError(
                        message="Session module is not configured.",
                        error_code="configuration.session.not_configured",
                    )
                session_key = self.config.get("session", {}).get(
                    "session_key", "auth"
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
    ) -> BaseSubject | dict[str, Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (str | None): Token type: "jwt", "paseto", "session" or None
                for auto-detect.

        Returns:
            BaseSubject | dict[str, Any]: Subject instance if a subject class
                is configured, otherwise the raw payload dict.

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

        return self._subject_from_payload(payload)

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
        jti: str | None,
    ) -> str:
        """Encode a payload with the configured PASETO module.

        Args:
            payload (dict[str, Any]): Payload.
            exp (int | None): Expiration in seconds.
            iss (str | None): Issuer.
            aud (str | None): Audience.
            jti (str | None): Token ID.

        Returns:
            str: PASETO token.
        """
        data = dict(payload)
        if exp is not None:
            data["exp"] = int(time.time()) + exp
        if iss is not None:
            data["iss"] = iss
        if aud is not None:
            data["aud"] = aud
        if jti is not None:
            data["jti"] = jti
        return self.paseto.encode(payload=data)
