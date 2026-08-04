# -*- coding: utf-8 -*-

import logging
import time
from typing import Any
import uuid

from jam.__deprecated__ import deprecated
from jam.aio.__base__ import BaseAsyncJam
from jam.exceptions import (
    JamConfigurationError,
    JamJWTExpired,
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamJWTNotYetValid,
)


logger = logging.getLogger(__name__)


class Jam(BaseAsyncJam):
    """Main async Jam instance."""

    MODULES: dict[str, str | dict[str, str]] = {
        "jose": {
            "jwt": "jam.jose.create_jwt_instance",
            "jws": "jam.jose.create_jws_instance",
            "jwe": "jam.jose.create_jwe_instance",
        },
        "session": "jam.aio.sessions.create_instance",
        "oauth2": "jam.aio.oauth2.create_instance",
        "paseto": "jam.paseto.create_instance",
        "otp": "jam.otp.__base__.OTPConfig",
    }

    @deprecated(
        "This method is deprecated; the JWT payload is generated automatically in accordance with the specification."
    )
    async def jwt_make_payload(
        self, exp: int | None, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Make JWT-specific payload.

        !!! Deprecated
                This method is deprecated; the JWT payload is generated automatically in accordance with the specification.

        Args:
            exp (int | None): Token expire
            data (dict[str, Any]): Data to payload

        Returns:
            dict[str, Any]: Payload
        """
        now = time.time()
        payload = {
            "iat": now,
            "exp": (now + exp) if exp else None,
            "jti": str(uuid.uuid4()),
        }
        payload = payload | data
        return payload

    @deprecated("Use jam.jwt_encode")
    async def jwt_create(self, payload: dict[str, Any]) -> str:
        """Create JWT token.

        !!! Deprecated
                Use Jam.jwt_encode

        Args:
            payload (dict[str, Any]): Data payload

        Returns:
            str: New token
        """
        assert self.jwt is not None
        logger.debug(
            f"Creating JWT token with payload keys: {list(payload.keys())}"
        )
        token = self.jwt.encode(payload=payload)
        logger.debug(
            f"JWT token created successfully, length: {len(token)} characters"
        )

        # white list checker
        if self.jwt.list and self.jwt.list.__list_type__ == "white":
            self.jwt.list.add(token)

        return token

    async def jwt_encode(
        self,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
        exp: int | None = None,
        nbf: int | None = None,
        jti: str | None = None,
        *,
        payload: dict[str, Any] | None = None,
        header: dict[str, Any] | None = None,
    ) -> str:
        """Encode the JWT with the given expire, header, and payload.

        Args:
            exp (int | None): The expiration time in seconds.
            nbf (int | None): The not-before time in seconds.
            iss (str | None): The issuer.
            sub (str | None): The subject.
            aud (str | None): The audience.
            jti (str | None): The JWT ID. If none use the JTI fabric function.
            header (dict[str, Any] | None): The header to include in the JWT.
            payload (dict[str, Any] | None): The payload to include in the JWT.

        Returns:
            str: The encoded JWT.
        """
        assert self.jwt is not None
        if not jti:
            jti = self.jwt.jti
        token = self.jwt.encode(
            iss=iss,
            sub=sub,
            aud=aud,
            exp=exp,
            nbf=nbf,
            jti=jti,
            payload=payload,
            header=header,
        )
        if self.jwt.list and self.jwt.list.__list_type__ == "white":
            self.jwt.list.add(token)
        return token

    async def jwt_decode(
        self,
        token: str,
        check_exp: bool = True,
        check_list: bool = True,
        check_nbf: bool = False,
        include_headers: bool = False,
    ) -> dict[str, Any]:
        """Verify and decode JWT token.

        Args:
            token (str): JWT token
            check_exp (bool): Check expire
            check_list (bool): Check white/black list. Docs: https://jam.makridenko.ru/jwt/lists/what/
            check_nbf (bool): Check not-before time
            include_headers (bool): Include headers in the decoded payload

        Returns:
            dict[str, Any]: Decoded payload

        Raises:
            JamJWTExpired: If token is expired
            JamJWTNotYetValid: If token is not yet valid (nbf claim)
            JamConfigurationError: If JWT list is not connected
            JamJWTNotInWhiteList: If token is not in white list
            JamJWTInBlackList: If token is in black list
        """
        assert self.jwt is not None
        logger.debug(
            f"Verifying JWT token (length: {len(token)} chars), check_exp={check_exp}, check_list={check_list}, check_nbf={check_nbf}"
        )
        data = self.jwt.decode(token)
        if "payload" in data:
            payload = data["payload"]
            headers = data.get("header")
        else:
            payload = data
            headers = None

        if check_exp and "exp" in payload:
            if payload["exp"] < time.time():
                raise JamJWTExpired

        if check_nbf and "nbf" in payload:
            if payload["nbf"] > time.time():
                raise JamJWTNotYetValid

        logger.debug(
            f"JWT token verified successfully, payload keys: {list(payload.keys())}"
        )

        if check_list:
            if not self.jwt.list:
                raise JamConfigurationError(
                    message="JWT list is not connected.",
                    error_code="configuration.jwt.list_not_connected",
                )
            else:
                match self.jwt.list.__list_type__:
                    case "white":
                        if not (self.jwt.list.check(token)):
                            raise JamJWTNotInWhiteList
                    case "black":
                        if self.jwt.list.check(token):
                            raise JamJWTInBlackList
                    case _:
                        raise JamConfigurationError(
                            message="Invalid JWT list type",
                            error_code="configuration.jwt.unknown_list_type",
                        )

        if include_headers and headers is not None:
            return {"header": headers, "payload": payload}
        return payload

    async def jws_sign(
        self,
        data: dict[str, Any] | str,
        header: dict[str, Any] | None = None,
    ) -> str:
        """Sign data using JWS.

        Args:
            data: Data to sign. If dict, will be JSON encoded.
            header: JWS header.

        Returns:
            str: JWS token.
        """
        assert self.jws is not None
        logger.debug(f"Signing data with JWS, header: {header}")
        token = self.jws.sign(header or {}, data)
        logger.debug(f"JWS token created, length: {len(token)}")
        return token

    async def jws_verify(self, token: str) -> dict[str, Any]:
        """Verify JWS token.

        Args:
            token: JWS token.

        Returns:
            dict[str, Any]: Decoded payload.
        """
        assert self.jws is not None
        logger.debug(f"Verifying JWS token, length: {len(token)}")
        result = self.jws.verify(token)
        logger.debug("JWS token verified successfully")
        return result

    async def jwe_encrypt(
        self,
        data: dict[str, Any] | str,
        header: dict[str, Any] | None = None,
    ) -> str:
        """Encrypt data using JWE.

        Args:
            data: Data to encrypt. If dict, will be JSON encoded.
            header: JWE header.

        Returns:
            str: JWE token.
        """
        assert self.jwe is not None
        logger.debug(f"Encrypting data with JWE, header: {header}")
        token = self.jwe.encrypt(
            self._serializer.dumps(data) if isinstance(data, dict) else data,
            header,
        )
        logger.debug(f"JWE token created, length: {len(token)}")
        return token

    async def jwe_decrypt(self, token: str) -> bytes:
        """Decrypt JWE token.

        Args:
            token: JWE token.

        Returns:
            bytes: Decrypted data.
        """
        assert self.jwe is not None
        logger.debug(f"Decrypting JWE token, length: {len(token)}")
        result = self.jwe.decrypt(token)
        logger.debug("JWE token decrypted successfully")
        return result

    async def session_create(
        self, session_key: str, data: dict[str, Any]
    ) -> str:
        """Create new session.

        Args:
            session_key (str): Key for session
            data (dict[str, Any]): Session data

        Returns:
            str: New session ID
        """
        assert self.session is not None
        logger.debug(
            f"Creating session with key: {session_key}, data keys: {list(data.keys())}"
        )
        session_id = await self.session.create(session_key, data)
        logger.debug(f"Session created successfully, session_id: {session_id}")
        return session_id

    async def session_get(self, session_id: str) -> dict[str, Any] | None:
        """Get data from session.

        Args:
            session_id (str): Session ID

        Returns:
            dict[str, Any] | None: Session data if exist
        """
        assert self.session is not None
        logger.debug(f"Getting session data for session_id: {session_id}")
        data = await self.session.get(session_id)
        if data:
            logger.debug(f"Session data retrieved, keys: {list(data.keys())}")
        else:
            logger.debug(f"Session {session_id} not found")
        return data

    async def session_delete(self, session_id: str) -> None:
        """Delete session.

        Args:
            session_id (str): Session ID
        """
        assert self.session is not None
        return await self.session.delete(session_id)

    async def session_update(
        self, session_id: str, data: dict[str, Any]
    ) -> None:
        """Update session data.

        Args:
            session_id (str): Session ID
            data (dict[str, Any]): New data

        """
        assert self.session is not None
        return await self.session.update(session_id, data)

    async def session_clear(self, session_key: str) -> None:
        """Delete all sessions by key.

        Args:
            session_key (str): Key of session
        """
        assert self.session is not None
        return await self.session.clear(session_key)

    async def session_rework(self, old_session_id: str) -> str:
        """Rework session.

        Args:
            old_session_id (str): Old session id

        Returns:
            str: New session id
        """
        assert self.session is not None
        return await self.session.rework(old_session_id)

    async def otp_code(
        self, secret: str | bytes, factor: int | None = None
    ) -> str:
        """Generates an OTP.

        Args:
            secret (str | bytes): User secret key.
            factor (int | None, optional): Unixtime for TOTP(if none, use now time) / Counter for HOTP.

        Returns:
            str: OTP code (fixed-length string).
        """
        assert self.otp is not None
        assert self._otp is not None
        return self._otp(
            secret=secret, digits=self.otp.digits, digest=self.otp.digest
        ).at(factor)

    async def otp_uri(
        self,
        secret: str,
        name: str,
        issuer: str,
        counter: int | None = None,
    ) -> str:
        """Generates an otpauth:// URI for Google Authenticator.

        Args:
            secret (str): User secret key.
            name (str): Account name (e.g., email).
            issuer (str): Service name (e.g., "GitHub").
            counter (int | None, optional): Counter (for HOTP). Default is None.

        Returns:
            str: A string of the form "otpauth://..."
        """
        assert self.otp is not None
        assert self._otp is not None
        return self._otp(
            secret=secret, digits=self.otp.digits, digest=self.otp.digest
        ).provisioning_uri(name=name, issuer=issuer, counter=counter)

    async def otp_verify_code(
        self,
        secret: str | bytes,
        code: str,
        factor: int | None = None,
        look_ahead: int | None = 1,
    ) -> bool:
        """Checks the OTP code, taking into account the acceptable window.

        Args:
            secret (str | bytes): User secret key.
            code (str): The code entered.
            factor (int | None, optional): Unixtime for TOTP(if none, use now time) / Counter for HOTP.
            look_ahead (int, optional): Acceptable deviation in intervals (±window(totp) / ±look ahead(hotp)). Default is 1.

        Returns:
            bool: True if the code matches, otherwise False.
        """
        assert self.otp is not None
        assert self._otp is not None
        return self._otp(
            secret=secret, digits=self.otp.digits, digest=self.otp.digest
        ).verify(code=code, factor=factor, look_ahead=look_ahead or 1)

    async def oauth2_get_authorized_url(
        self, provider: str, scope: list[str], **extra_params: Any
    ) -> str:
        """Generate full OAuth2 authorization URL.

        Args:
            provider (str): Provider name
            scope (list[str]): Auth scope
            extra_params (Any): Extra ath params

        Returns:
            str: Authorization url
        """
        from jam.exceptions import JamConfigurationError

        if self.oauth2 is None or provider not in self.oauth2:
            raise JamConfigurationError(
                message=f"Provider {provider} not configured",
                error_code="oauth2.configuration.provider_not_configured",
            )
        return await self.oauth2[provider].get_authorization_url(
            scope, **extra_params
        )

    async def oauth2_fetch_token(
        self,
        provider: str,
        code: str,
        grant_type: str = "authorization_code",
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Exchange authorization code for access token.

        Args:
            provider (str): Provider name
            code (str): OAuth2 code
            grant_type (str): Type of oauth2 grant
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: OAuth2 token
        """
        from jam.exceptions import JamOAuth2ProviderNotConfigured

        if self.oauth2 is None or provider not in self.oauth2:
            raise JamOAuth2ProviderNotConfigured(details={"provider": provider})
        return await self.oauth2[provider].fetch_token(
            code, grant_type, **extra_params
        )

    async def oauth2_refresh_token(
        self,
        provider: str,
        refresh_token: str,
        grant_type: str = "refresh_token",
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Use refresh token to obtain a new access token.

        Args:
            provider (str): Provider name
            refresh_token (str): Refresh token
            grant_type (str): Grant type
            extra_params (Any): Extra auth params if needed

        Returns:
            dict: Refresh token
        """
        from jam.exceptions import JamOAuth2ProviderNotConfigured

        if self.oauth2 is None or provider not in self.oauth2:
            raise JamOAuth2ProviderNotConfigured(details={"provider": provider})
        return await self.oauth2[provider].refresh_token(
            refresh_token, grant_type, **extra_params
        )

    async def oauth2_client_credentials_flow(
        self,
        provider: str,
        scope: list[str] | None = None,
        **extra_params: Any,
    ) -> dict[str, Any]:
        """Obtain access token using client credentials flow (no user interaction).

        Args:
            provider (str): OAuth2 provider
            scope (list[str] | None): Auth scope
            extra_params (Any): Extra auth params if needed

        Raises:
            JamOAuth2EmptyRaw: If response is empty
            JamOAuth2Error: HTTP error

        Returns:
            dict: JSON with access token
        """
        from jam.exceptions import JamOAuth2ProviderNotConfigured

        if self.oauth2 is None or provider not in self.oauth2:
            raise JamOAuth2ProviderNotConfigured(details={"provider": provider})
        return await self.oauth2[provider].client_credentials_flow(
            scope, **extra_params
        )

    async def paseto_make_payload(
        self, exp: int | None = None, **data: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate payload for PASETO.

        Args:
            exp (int | None): Token expire
            data (dict[str, Any]): Custom data

        Returns:
            dict: Payload
        """
        from jam.paseto.utils import payload_maker

        return payload_maker(expire=exp, data=data)

    async def paseto_create(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | None,
    ) -> str:
        """Create new PASETO.

        Args:
            payload (dict[str, Any]): Payload
            footer (dict | str  | None): Footer

        Returns:
            str: New token
        """
        assert self.paseto is not None
        return self.paseto.encode(payload=payload, footer=footer)

    async def paseto_decode(
        self, token: str, check_exp: bool = True, check_list: bool = True
    ) -> dict[str, dict[str, Any] | str | None]:
        """Decode PASETO.

        Args:
            token (str): Token
            check_exp (bool): Check exp in payload
            check_list (bool): Check token in list

        Returns:
            dict: {'payload' PAYLOAD, 'footer': FOOTER}
        """
        assert self.paseto is not None
        payload, footer = self.paseto.decode(token)
        return {"payload": payload, "footer": footer}
