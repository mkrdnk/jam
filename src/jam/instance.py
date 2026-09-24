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
    JamTokenInDenyList,
    JamTokenNotInAllowList,
)
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
            via (JamIssueType): Token type: "jwt", "paseto", "session",
                "macaroon", or "saml".
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
                credential = self.macaroon.issue(
                    payload,
                    exp=exp,
                    nbf=nbf,
                    iss=iss,
                    aud=aud,
                    jti=jti,
                )
                self._register_allowlisted_token(
                    self._macaroon_list, credential
                )
                return credential
            case "jwt":
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
                credential = self._issue_paseto(
                    payload, exp, iss, aud, nbf, jti
                )
                logger.info("Issued credential via=paseto")
                return credential
            case "saml":
                credential = self._issue_saml(payload, exp, iss, aud, nbf, jti)
                self._register_allowlisted_token(self._saml_list, credential)
                logger.info("Issued credential via=saml")
                return credential
            case "session":
                session = self.session
                session_key = (
                    (self.config or {})
                    .get("session", {})
                    .get("session_key", "auth")
                )
                credential = session.create(session_key, payload)
                logger.info("Issued credential via=session")
                return credential
            case _:
                logger.warning(
                    "Cannot issue credential via unsupported type=%s", via
                )
                raise JamConfigurationError(
                    message=f"Unknown 'via' type: {via}. "
                    "Available: jwt, paseto, session, macaroon, saml",
                    error_code="configuration.issue_unknown_via",
                )

    def authenticate(
        self,
        token: str,
        via: JamAuthType,
        *,
        discharges: Sequence[str | bytes] | None = None,
    ) -> Principal[Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (JamAuthType): Token type: "jwt", "jwe", "paseto",
                "session", "macaroon", or "saml".
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
                self._check_token_list(self._macaroon_list, token)
                payload, constraints = self.macaroon.authenticate(
                    token,
                    discharges=() if discharges is None else discharges,
                )
            case "jwt":
                payload = self.jwt.decode(token)["payload"]
            case "jwe":
                jwt = self.jwt
                if jwt.jwe is None:
                    raise JamConfigurationError(
                        message="JWE module is not configured.",
                        error_code="configuration.jwe.not_configured",
                    )
                decrypted = jwt.decrypt(token)
                if not isinstance(decrypted, dict):
                    raise JamJWSVerificationError(
                        message="JWE payload is not a serialized object.",
                    )
                payload = decrypted
            case "paseto":
                payload, _footer = self.paseto.decode(token)
            case "saml":
                self._check_token_list(self._saml_list, token)
                payload = self._authenticate_saml(token)
            case "session":
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
                    "Available: jwt, jwe, paseto, session, macaroon, saml",
                    error_code="configuration.authenticate_unknown_via",
                )

        logger.info("Authenticated credential via=%s", via)
        return Principal(
            subject=self._subject_from_payload(payload),
            claims=dict(payload),
            token_type=via,
            constraints=constraints,
        )

    def close(self) -> None:
        """Close synchronous resources owned by this instance.

        Modules shared by multiple token-list references are closed only once
        for each invocation.
        """
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
            close = getattr(module, "close", None)
            if callable(close):
                close()

    def __enter__(self) -> "Jam":
        """Enter a synchronous resource context."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close owned resources when leaving a context."""
        self.close()

    @staticmethod
    def _register_allowlisted_token(token_list: Any, token: str) -> None:
        """Register an issued token when an allowlist is configured."""
        if token_list is not None and token_list.__list_type__ == "white":
            token_list.add(token)

    @staticmethod
    def _check_token_list(token_list: Any, token: str) -> None:
        """Enforce an optional token allowlist or denylist."""
        if token_list is None:
            return
        listed = token_list.check(token)
        if token_list.__list_type__ == "white" and not listed:
            raise JamTokenNotInAllowList
        if token_list.__list_type__ == "black" and listed:
            raise JamTokenInDenyList
