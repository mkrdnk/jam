# -*- coding: utf-8 -*-

from collections.abc import Sequence
import logging
from typing import Any

from jam.__base__ import BaseJam
from jam.__core__ import JamAuthType, JamIssueType
from jam.authz import AuthorizationContext, Principal
from jam.exceptions import (
    JamConfigurationError,
    JamJWSVerificationError,
    JamSessionNotFound,
)
from jam.macaroons import Macaroon
from jam.subject import BaseSubject


logger = logging.getLogger(__name__)


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
        return self._authorize(principal, permission, context)

    def issue(
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
        """Issue a token or session for a subject.

        Args:
            subject (BaseSubject): Subject instance or dict with an "id".
            via (JamIssueType): Token type: "jwt", "paseto" or "session".
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
        logger.debug(
            "Issuing credential via=%s with claim_count=%d",
            via,
            len(payload),
        )
        match via:
            case "macaroon":
                if self.macaroon is None:
                    raise JamConfigurationError(
                        message="Macaroon module is not configured.",
                        error_code="configuration.macaroon.not_configured",
                    )
                return self.macaroon.issue(
                    payload,
                    exp=exp,
                    nbf=nbf,
                    iss=iss,
                    aud=aud,
                    jti=jti,
                )
            case "jwt":
                if self.jwt is None:
                    raise JamConfigurationError(
                        message="JWT module is not configured.",
                        error_code="configuration.jwt.not_configured",
                    )
                credential = self.jwt.encode(
                    payload=payload,
                    exp=exp,
                    iss=iss,
                    aud=aud,
                    nbf=nbf,
                    jti=jti,
                )
                logger.info("Issued credential via=jwt")
                return credential
            case "paseto":
                if self.paseto is None:
                    raise JamConfigurationError(
                        message="PASETO module is not configured.",
                        error_code="configuration.paseto.not_configured",
                    )
                credential = self._issue_paseto(
                    payload, exp, iss, aud, nbf, jti
                )
                logger.info("Issued credential via=paseto")
                return credential
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
                credential = self.session.create(session_key, payload)
                logger.info("Issued credential via=session")
                return credential
            case _:
                logger.warning(
                    "Cannot issue credential via unsupported type=%s", via
                )
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, paseto, session, macaroon",
                    error_code="configuration.issue_unknown_via",
                )

    def authenticate(
        self,
        token: str,
        via: JamAuthType,
        *,
        discharges: Sequence[str | bytes | Macaroon] | None = None,
    ) -> Principal[Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (JamAuthType): Token type: "jwt", "jwe", "paseto" or
                "session".
            discharges: Bound discharges for third-party caveats.

        Returns:
            Principal: Authenticated subject and credential claims.

        Raises:
            JamConfigurationError: If no matching module is configured.
            JamSessionNotFound: If a session does not exist.
        """
        logger.debug("Authenticating credential via=%s", via)
        constraints = ()
        match via:
            case "macaroon":
                if self.macaroon is None:
                    raise JamConfigurationError(
                        message="Macaroon module is not configured.",
                        error_code="configuration.macaroon.not_configured",
                    )
                payload, constraints = self.macaroon.authenticate(
                    token,
                    discharges=() if discharges is None else discharges,
                )
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
                    logger.warning(
                        "Session authentication failed: session not found"
                    )
                    raise JamSessionNotFound(details={"session_id": token})
                payload = data
            case _:
                logger.warning(
                    "Cannot authenticate credential via unsupported type=%s",
                    via,
                )
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, jwe, paseto, session, macaroon",
                    error_code="configuration.authenticate_unknown_via",
                )

        logger.info("Authenticated credential via=%s", via)
        return Principal(
            subject=self._subject_from_payload(payload),
            claims=dict(payload),
            token_type=via,
            constraints=constraints,
        )
