# -*- coding: utf-8 -*-

from __future__ import annotations

import dataclasses
import logging
import math
import time
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, cast

from jam.__base_encoder__ import BaseEncoder
from jam.authz import (
    AuthorizationContext,
    BasePolicy,
    Policy,
    Principal,
)
from jam.encoders import JsonEncoder
from jam.exceptions import (
    JamConfigurationError,
    JamJWSVerificationError,
    JamSessionExpired,
    JamSessionInvalidClaim,
    JamSessionNotYetValid,
    JamValidationError,
)
from jam.paseto.utils import _format_registered_datetime
from jam.plugins.__base__ import BasePlugin
from jam.subject import BaseSubject
from jam.utils.config_maker import __config_maker__, __module_loader__


if TYPE_CHECKING:
    from jam.jose import JWE, JWS, JWT
    from jam.macaroons import CaveatRegistry, MacaroonModule
    from jam.otp import BaseOTP
    from jam.paseto import BasePASETO
    from jam.saml import SAML


logger = logging.getLogger(__name__)

JamIssueType = Literal["jwt", "paseto", "session", "macaroon", "saml"]
JamAuthType = Literal["jwt", "jwe", "paseto", "session", "macaroon", "saml"]

_SessionT = TypeVar("_SessionT")
_OAuth2ClientT = TypeVar("_OAuth2ClientT")
_ModuleT = TypeVar("_ModuleT")


class _JamCore(Generic[_SessionT, _OAuth2ClientT]):
    """Configuration and pure operations shared by sync and async facades."""

    _async = False

    subject: type[BaseSubject] = BaseSubject
    config: dict[str, Any] | None = None

    _jwt: JWT | None = None
    _jws: JWS | None = None
    _jwe: JWE | None = None
    _jose: dict[str, JWT | JWS | JWE] | None = None
    _session: _SessionT | None = None
    _oauth2: dict[str, _OAuth2ClientT] | None = None
    _otp: type[BaseOTP] | None = None
    _paseto: BasePASETO | None = None
    _saml: SAML | None = None
    _macaroon: MacaroonModule | None = None
    keychains: dict[str, Any]
    lists: dict[str, Any]
    _jwt_list: Any = None
    _paseto_list: Any = None
    _macaroon_list: Any = None
    _saml_list: Any = None
    _policy: BasePolicy

    def __init__(
        self,
        config: str | dict[str, Any] | None = None,
        pointer: str = "jam",
        *,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        subject: type[BaseSubject] | None = None,
        plugins: list[type[BasePlugin]] | None = None,
        caveat_registry: CaveatRegistry | None = None,
    ) -> None:
        """Initialize instance.

        Args:
            config (Union[str, dict[str, Any], None]): Configuration dict or
                file path. Defaults to the class attribute.
            pointer (str): Config pointer. Defaults to "jam".
            serializer (Union[BaseEncoder, type[BaseEncoder]]): Serializer.
            subject (type[BaseSubject] | None): Subject class override.
            plugins (list[type[BasePlugin]] | None): List of plugins.
            caveat_registry: Custom caveat registry owned by this instance.
        """
        if config is None:
            config = self.config or {}
        config = __config_maker__(config, pointer)
        serializer = self.__build_main_config(config, serializer)

        self.config = config
        self._serializer = serializer
        self._plugins = []
        self._caveat_registry = caveat_registry

        if subject is not None:
            self.subject = subject

        self._jwt = None
        self._jws = None
        self._jwe = None
        self._jose = None
        self._session = None
        self._oauth2 = None
        self._otp = None
        self._paseto = None
        self._saml = None
        self._macaroon = None
        self.keychains = {}
        self.lists = {}
        self._jwt_list = None
        self._paseto_list = None
        self._macaroon_list = None
        self._saml_list = None
        self._policy: BasePolicy = Policy()

        logger.debug(
            "Initializing %s with serializer=%s",
            type(self).__name__,
            serializer,
        )
        self.__build_instance(config)
        logger.debug(
            "BaseJam initialization complete. Modules loaded:\n"
            " jwt=%s, jws=%s, jwe=%s, session=%s, oauth2=%s, paseto=%s, "
            "otp=%s, saml=%s",
            self._jwt is not None,
            self._jws is not None,
            self._jwe is not None,
            self._session is not None,
            self._oauth2 is not None,
            self._paseto is not None,
            self._otp is not None,
            self._saml is not None,
        )

    @staticmethod
    def _require_module(
        module: _ModuleT | None,
        name: str,
        display_name: str,
    ) -> _ModuleT:
        """Return a configured module or raise a stable configuration error."""
        if module is None:
            raise JamConfigurationError(
                message=f"{display_name} module is not configured.",
                error_code=f"configuration.{name}.not_configured",
            )
        return module

    @property
    def jwt(self) -> JWT:
        """Return the configured JWT module."""
        return self._require_module(self._jwt, "jwt", "JWT")

    @jwt.setter
    def jwt(self, module: Any | None) -> None:
        self._jwt = module

    @property
    def jws(self) -> JWS:
        """Return the configured JWS module."""
        return self._require_module(self._jws, "jws", "JWS")

    @jws.setter
    def jws(self, module: Any | None) -> None:
        self._jws = module

    @property
    def jwe(self) -> JWE:
        """Return the configured JWE module."""
        return self._require_module(self._jwe, "jwe", "JWE")

    @jwe.setter
    def jwe(self, module: Any | None) -> None:
        self._jwe = module

    @property
    def jose(self) -> dict[str, JWT | JWS | JWE]:
        """Return the configured JOSE modules."""
        return self._require_module(self._jose, "jose", "JOSE")

    @jose.setter
    def jose(self, modules: dict[str, Any] | None) -> None:
        self._jose = modules

    @property
    def session(self) -> _SessionT:
        """Return the configured session module."""
        return self._require_module(self._session, "session", "Session")

    @session.setter
    def session(self, module: Any | None) -> None:
        self._session = module

    @property
    def oauth2(self) -> dict[str, _OAuth2ClientT]:
        """Return the configured OAuth2 clients."""
        return self._require_module(self._oauth2, "oauth2", "OAuth2")

    @oauth2.setter
    def oauth2(self, clients: dict[str, Any] | None) -> None:
        self._oauth2 = clients

    @property
    def otp(self) -> type[BaseOTP]:
        """Return the configured OTP module."""
        return self._require_module(self._otp, "otp", "OTP")

    @otp.setter
    def otp(self, module: Any | None) -> None:
        self._otp = module

    @property
    def paseto(self) -> BasePASETO:
        """Return the configured PASETO module."""
        return self._require_module(self._paseto, "paseto", "PASETO")

    @paseto.setter
    def paseto(self, module: Any | None) -> None:
        self._paseto = module

    @property
    def jwt_list(self) -> Any | None:
        """Return the configured JWT token list, if any."""
        return self._jwt_list

    @property
    def paseto_list(self) -> Any | None:
        """Return the configured PASETO token list, if any."""
        return self._paseto_list

    @property
    def macaroon_list(self) -> Any | None:
        """Return the configured Macaroon token list, if any."""
        return self._macaroon_list

    @property
    def saml_list(self) -> Any | None:
        """Return the configured SAML token list, if any."""
        return self._saml_list

    @property
    def saml(self) -> SAML:
        """Return the configured SAML module."""
        return self._require_module(self._saml, "saml", "SAML")

    @saml.setter
    def saml(self, module: Any | None) -> None:
        self._saml = module

    @property
    def macaroon(self) -> MacaroonModule:
        """Return the configured Macaroon module.

        Raises:
            JamConfigurationError: If the Macaroon module is not configured.
        """
        return self._require_module(self._macaroon, "macaroon", "Macaroon")

    @macaroon.setter
    def macaroon(self, module: Any | None) -> None:
        """Replace the configured Macaroon module."""
        self._macaroon = module

    def _authorize(
        self,
        principal: Principal[Any] | BaseSubject | dict[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Enforce credential restrictions before the configured policy."""
        if isinstance(principal, Principal):
            if (
                principal.token_type == "macaroon"
                and not principal.has_permission(permission)
            ):
                return False
            if principal.constraints:
                context = context or AuthorizationContext()
                try:
                    if not all(
                        constraint.check(principal, permission, context)
                        for constraint in principal.constraints
                    ):
                        return False
                except JamValidationError:
                    return False
        return self._policy.check(principal, permission, context)

    def _authenticate_jwe(self, token: str) -> dict[str, Any]:
        """Decrypt an encrypted, signed JWT for authentication.

        JWE alone proves that a sender could encrypt to the recipient. With
        asymmetric key management, that capability is intentionally public,
        so an unsigned JWE cannot establish the identity of its issuer.

        Args:
            token: JWE compact serialization containing a nested JWS.

        Returns:
            dict[str, Any]: Verified claims from the nested JWS.

        Raises:
            JamConfigurationError: If JWE or nested JWS is not configured.
            JamJWSVerificationError: If the authenticated payload is not an
                object.
        """
        jwt = self.jwt
        if jwt.jwe is None:
            raise JamConfigurationError(
                message="JWE module is not configured.",
                error_code="configuration.jwe.not_configured",
            )
        if jwt.jws is None:
            raise JamConfigurationError(
                message=(
                    "JWE authentication requires a nested JWS. "
                    "Configure both 'alg' and 'enc'."
                ),
                error_code="configuration.jwe.authentication_requires_jws",
            )

        decrypted = jwt.decrypt(token)
        if not isinstance(decrypted, dict):
            raise JamJWSVerificationError(
                message="JWE payload is not a serialized object.",
            )
        from jam.jose.jwt import _validate_registered_claims

        _validate_registered_claims(decrypted)
        return decrypted

    def __build_main_config(
        self,
        config: dict[str, Any],
        default_serializer: BaseEncoder | type[BaseEncoder],
    ) -> BaseEncoder | type[BaseEncoder]:
        """Build the serializer from config or use the default.

        Args:
            config (dict[str, Any]): Configuration dictionary
            default_serializer (BaseEncoder | type[BaseEncoder]): Default serializer

        Returns:
            BaseEncoder | type[BaseEncoder]: Resolved serializer
        """
        serializer = default_serializer

        if "serializer" in config:
            serializer_cfg = config["serializer"]
            if isinstance(serializer_cfg, str):
                serializer = cast(
                    "BaseEncoder | type[BaseEncoder]",
                    __module_loader__(serializer_cfg),
                )
            elif isinstance(serializer_cfg, type) and issubclass(
                serializer_cfg, BaseEncoder
            ):
                serializer = serializer_cfg
            elif isinstance(serializer_cfg, BaseEncoder):
                serializer = serializer_cfg

        return serializer

    def __build_instance(self, config: dict[str, Any]) -> None:
        """Build module instances from configuration.

        Args:
            config (dict[str, Any]): Configuration
        """
        jose_cfg = config.get("jose") or {}
        if not isinstance(jose_cfg, dict):
            jose_cfg = {}
        self.jose = {}
        keychain_cfg = config.get("keychains") or {}
        lists_cfg = config.get("lists") or {}

        if not isinstance(lists_cfg, dict):
            raise JamConfigurationError(
                message="Token lists configuration must be a mapping.",
                error_code="configuration.lists.invalid",
            )

        if self._async:
            from jam.aio.lists import build_list as build_token_list
        else:
            from jam.lists import build_list as build_token_list

        for name, list_cfg in lists_cfg.items():
            if not isinstance(name, str) or not name:
                raise JamConfigurationError(
                    message="Token list names must be non-empty strings.",
                    error_code="configuration.lists.invalid_name",
                )
            if isinstance(list_cfg, dict):
                list_cfg = list_cfg.copy()
                list_cfg.setdefault("prefix", name)
                if list_cfg.get("backend") == "json":
                    list_cfg.setdefault("json_path", f"{name}.json")
            self.lists[name] = build_token_list(list_cfg)

        def get_token_list(list_config: Any) -> Any | None:
            if list_config is None:
                return None
            if isinstance(list_config, str):
                try:
                    return self.lists[list_config]
                except KeyError as exc:
                    raise JamConfigurationError(
                        message=f"Token list '{list_config}' is not configured.",
                        error_code="configuration.lists.not_configured",
                    ) from exc
            return build_token_list(list_config)

        def get_keychain(
            name: str, algorithm: str, purpose: str | None = None
        ) -> Any:
            from jam.keychain import FileStorage, Memory

            if name in self.keychains:
                return self.keychains[name]
            cfg = keychain_cfg.get(name)
            if not isinstance(cfg, dict):
                raise JamConfigurationError(
                    message=f"KeyChain '{name}' is not configured.",
                    error_code="configuration.keychain.not_configured",
                )
            chain_type = cfg.get("type")
            chain_algorithm = cfg.get("algorithm", algorithm)
            chain_purpose = cfg.get("purpose", purpose)
            if chain_type == "Memory":
                chain = Memory(algorithm=chain_algorithm, purpose=chain_purpose)
            elif chain_type == "FileStorage":
                path = cfg.get("path")
                if not path:
                    raise JamConfigurationError(
                        message=f"FileStorage KeyChain '{name}' needs a path.",
                        error_code="configuration.keychain.missing_path",
                    )
                chain = FileStorage(
                    path=path, algorithm=chain_algorithm, purpose=chain_purpose
                )
            else:
                raise JamConfigurationError(
                    message=f"Unknown KeyChain type: {chain_type}.",
                    error_code="configuration.keychain.unknown_type",
                )
            self.keychains[name] = chain
            return chain

        if "macaroon" in config:
            from jam.macaroons import create_instance

            macaroon_cfg = config["macaroon"]
            if isinstance(macaroon_cfg, dict):
                macaroon_cfg = macaroon_cfg.copy()
                self._macaroon_list = get_token_list(
                    macaroon_cfg.pop("list", None)
                )
            self.macaroon = create_instance(
                macaroon_cfg,
                resolve_keychain=get_keychain,
                registry=self._caveat_registry,
            )

        jwt_cfg = jose_cfg.get("jwt")
        if jwt_cfg is not None:
            from jam.jose import JWT

            jwt_cfg = jwt_cfg.copy()
            chain_name = jwt_cfg.pop("keychain", None)
            list_cfg = jwt_cfg.pop("list", None)
            self._jwt_list = get_token_list(list_cfg)
            self.jwt = JWT(
                config=jwt_cfg,
                list=None if self._async else self._jwt_list,
                keychain=(
                    get_keychain(chain_name, jwt_cfg.get("alg", "HS256"))
                    if chain_name
                    else None
                ),
            )
            self.jose["jwt"] = self.jwt

        jws_cfg = jose_cfg.get("jws")
        if jws_cfg is not None:
            from jam.jose import JWS

            self.jws = JWS(config=jws_cfg)
            self.jose["jws"] = self.jws

        jwe_cfg = jose_cfg.get("jwe")
        if jwe_cfg is not None:
            from jam.jose import JWE

            self.jwe = JWE(config=jwe_cfg)
            self.jose["jwe"] = self.jwe

        if not self.jose:
            self.jose = None

        session_cfg = config.get("session")
        if isinstance(session_cfg, dict):
            cfg = session_cfg.copy()
            session_type = cfg.pop("type", None)
            session_serializer = cfg.pop("serializer", self._serializer)
            if self._async:
                from jam.aio.sessions import (
                    SUPPORTED_SESSION_TYPES,
                    create_instance,
                )

                if session_type not in SUPPORTED_SESSION_TYPES:
                    raise JamConfigurationError(
                        message=(
                            f"Unknown session type: {session_type}. "
                            f"Available: {list(SUPPORTED_SESSION_TYPES)}"
                        ),
                        error_code="configuration.session.unknown_type",
                    )
                self.session = create_instance(
                    session_type=session_type,
                    serializer=session_serializer,
                    **cfg,
                )
            else:
                from jam.sessions import REGISTRY as SESSION_REGISTRY

                if session_type not in SESSION_REGISTRY:
                    raise JamConfigurationError(
                        message=(
                            f"Unknown session type: {session_type}. "
                            f"Available: {list(SESSION_REGISTRY)}"
                        ),
                        error_code="configuration.session.unknown_type",
                    )
                module_cls = SESSION_REGISTRY[session_type]
                self.session = module_cls(
                    config=cfg,
                    session_type=session_type,
                    serializer=session_serializer,
                )

        oauth2_cfg = config.get("oauth2")
        if isinstance(oauth2_cfg, dict) and oauth2_cfg:
            if self._async:
                from jam.aio.oauth2 import build_clients
            else:
                from jam.oauth2 import build_clients

            self.oauth2 = build_clients(
                oauth2_cfg,
                serializer=self._serializer,
            )

        paseto_cfg = config.get("paseto")
        if isinstance(paseto_cfg, dict):
            from jam.paseto import REGISTRY as PASETO_REGISTRY

            cfg = paseto_cfg.copy()
            version = cfg.pop("version", None)
            chain_name = cfg.pop("keychain", None)
            list_cfg = cfg.pop("list", None)
            self._paseto_list = get_token_list(list_cfg)
            if version not in PASETO_REGISTRY:
                raise JamConfigurationError(
                    message=(
                        f"Unknown PASETO version: {version}. "
                        f"Available: {list(PASETO_REGISTRY)}"
                    ),
                    error_code="configuration.paseto.unknown_version",
                )
            module_cls = PASETO_REGISTRY[version]
            self.paseto = module_cls(
                config=cfg,
                list=None if self._async else self._paseto_list,
                keychain=(
                    get_keychain(
                        chain_name,
                        algorithm={
                            "v1": "RS384",
                            "v2": "EDDSA",
                            "v3": "ES384",
                            "v4": "EDDSA",
                        }.get(version, "HS256")
                        if cfg.get("purpose") == "public"
                        else "HS256",
                        purpose=cfg.get("purpose"),
                    )
                    if chain_name
                    else None
                ),
            )

        saml_cfg = config.get("saml")
        if isinstance(saml_cfg, dict):
            from jam.saml import SAML, BaseSAML

            cfg = saml_cfg.copy()
            cfg.pop("audience", None)
            cfg.pop("expected_issuer", None)
            chain_name = cfg.pop("keychain", None)
            self._saml_list = get_token_list(cfg.pop("list", None))
            custom_module = cfg.pop("custom_module", None)
            module_cls = (
                __module_loader__(custom_module) if custom_module else SAML
            )
            if chain_name is not None:
                cfg["keychain"] = get_keychain(chain_name, "RS256")
            self.saml = module_cls(**cfg)
            if not isinstance(self.saml, BaseSAML):
                raise JamConfigurationError(
                    message="Configured SAML module must implement BaseSAML.",
                    error_code="configuration.saml.invalid_module",
                )

        for chain_name, chain_config in keychain_cfg.items():
            if (
                isinstance(chain_config, dict)
                and chain_name not in self.keychains
            ):
                get_keychain(
                    chain_name,
                    algorithm=chain_config.get("algorithm", "HS256"),
                    purpose=chain_config.get("purpose"),
                )

        otp_cfg = config.get("otp")
        if isinstance(otp_cfg, dict):
            from jam.otp import create_instance as create_otp

            otp_type = otp_cfg.get("type")
            if otp_type not in ("hotp", "totp"):
                raise JamConfigurationError(
                    message=(
                        f"Unknown OTP type: {otp_type}. Available: hotp, totp"
                    ),
                    error_code="configuration.otp.unknown_type",
                )
            self.otp = create_otp(**otp_cfg)

        authz_cfg = config.get("authz")
        if isinstance(authz_cfg, dict):
            module = authz_cfg.get("module")
            if module is not None:
                policy_cls = __module_loader__(module)
                self._policy = policy_cls(authz_cfg.get("rules") or {})
            else:
                self._policy = Policy(rules=authz_cfg.get("rules") or {})

    def _subject_from_payload(self, payload: dict[str, Any]) -> Any:
        """Build a subject from a token/session payload.

        Args:
            payload (dict[str, Any]): Decoded payload.

        Returns:
            Any: Subject instance or dict if no subject class is configured.
        """
        data = dict(payload)
        if "id" not in data and "sub" in data:
            data["id"] = data["sub"]
        if not dataclasses.is_dataclass(self.subject):
            return data
        field_names = {f.name for f in dataclasses.fields(self.subject)}
        subject_data = {k: v for k, v in data.items() if k in field_names}
        return self.subject.from_dict(subject_data)

    @staticmethod
    def _prepare_payload(
        subject: BaseSubject | dict[str, Any],
        permissions: list[str] | None,
        claims: dict[str, Any],
    ) -> dict[str, Any]:
        """Build and validate a credential payload."""
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
        return payload

    @staticmethod
    def _prepare_session_payload(
        payload: dict[str, Any],
        exp: int | None,
        iss: str | None,
        aud: str | None,
        nbf: int | None,
        jti: str | None,
    ) -> dict[str, Any]:
        """Add session metadata using the same relative-time API as tokens."""
        data = dict(payload)
        now = int(time.time())
        if exp is not None:
            data["exp"] = now + exp
        if nbf is not None:
            data["nbf"] = now + nbf
        if iss is not None:
            data["iss"] = iss
        if aud is not None:
            data["aud"] = aud
        if jti is not None:
            data["jti"] = jti
        return data

    @staticmethod
    def _validate_session_payload(payload: dict[str, Any]) -> None:
        """Reject sessions outside their validity window."""
        now = int(time.time())

        def numeric_date(claim: str) -> int | float:
            value = payload[claim]
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or (isinstance(value, float) and not math.isfinite(value))
            ):
                raise JamSessionInvalidClaim(
                    details={"claim": claim, "value": value}
                )
            return value

        if "exp" in payload:
            expires_at = numeric_date("exp")
            if now >= expires_at:
                raise JamSessionExpired(details={"exp": expires_at, "now": now})

        if "nbf" in payload:
            valid_from = numeric_date("nbf")
            if valid_from > now:
                raise JamSessionNotYetValid(
                    details={"nbf": valid_from, "now": now}
                )

    def _issue_paseto(
        self,
        payload: dict[str, Any],
        exp: int | None,
        iss: str | None,
        aud: str | None,
        nbf: int | None,
        jti: str | None,
    ) -> str:
        """Encode a payload with the configured PASETO module."""
        paseto = self.paseto
        data = dict(payload)
        now = int(time.time())
        if exp is not None:
            data["exp"] = _format_registered_datetime(now + exp)
        if nbf is not None:
            data["nbf"] = _format_registered_datetime(now + nbf)
        if iss is not None:
            data["iss"] = iss
        if aud is not None:
            data["aud"] = aud
        if jti is not None:
            data["jti"] = jti
        return paseto.encode(payload=data)

    def _issue_saml(
        self,
        payload: dict[str, Any],
        exp: int | None,
        iss: str | None,
        aud: str | None,
        nbf: int | None,
        jti: str | None,
    ) -> str:
        """Build a Base64-encoded SAML response for HTTP-POST binding."""
        from jam.saml.binding import encode_post

        saml = self.saml
        saml_config = (self.config or {}).get("saml") or {}
        issuer = iss or saml_config.get("entity_id")
        audience = aud or saml_config.get("audience")
        destination = saml_config.get("acs_url")
        if not issuer:
            raise JamConfigurationError(
                message="SAML issuance requires 'iss' or 'saml.entity_id'.",
                error_code="configuration.saml.missing_issuer",
            )
        if not audience:
            raise JamConfigurationError(
                message="SAML issuance requires 'aud' or 'saml.audience'.",
                error_code="configuration.saml.missing_audience",
            )
        if not destination:
            raise JamConfigurationError(
                message="SAML issuance requires 'saml.acs_url'.",
                error_code="configuration.saml.missing_acs_url",
            )

        attributes = dict(payload)
        subject = attributes.pop("sub", None)
        if subject is None:
            raise JamConfigurationError(
                message="SAML issuance requires a subject with an 'id'.",
                error_code="configuration.saml.missing_subject",
            )
        response = saml.build_response(
            subject=str(subject),
            attributes=attributes,
            issuer=issuer,
            audience=audience,
            destination=destination,
            expires_in=exp,
            not_before=nbf,
            assertion_id=jti,
        )
        return encode_post(response)

    def _authenticate_saml(
        self,
        token: str,
        *,
        expected_in_response_to: str | None = None,
    ) -> dict[str, Any]:
        """Validate a SAML response and convert its assertion to claims."""
        from jam.exceptions import JamSAMLValidationError
        from jam.saml.xml import STATUS_SUCCESS

        saml = self.saml
        saml_config = (self.config or {}).get("saml") or {}
        response = saml.parse_response(
            token,
            binding="post",
            audience=saml_config.get("audience")
            or saml_config.get("entity_id"),
            issuer=saml_config.get("expected_issuer"),
            expected_in_response_to=expected_in_response_to,
        )
        assertion = response.assertion
        if (
            response.status_code != STATUS_SUCCESS
            or assertion is None
            or assertion.subject is None
            or not assertion.subject.name_id
        ):
            raise JamSAMLValidationError(
                message="SAML response has no successful subject assertion."
            )

        claims = dict(assertion.attributes)
        permissions = claims.get("permissions")
        if isinstance(permissions, str):
            claims["permissions"] = [permissions]
        claims.update(
            {
                "sub": assertion.subject.name_id,
                "iss": assertion.issuer,
                "jti": assertion.id,
            }
        )
        conditions = assertion.conditions
        if conditions is not None:
            audiences = conditions.audience_restriction
            if audiences:
                claims["aud"] = (
                    audiences[0] if len(audiences) == 1 else list(audiences)
                )
            if conditions.not_before is not None:
                claims["nbf"] = int(conditions.not_before.timestamp())
            if conditions.not_on_or_after is not None:
                claims["exp"] = int(conditions.not_on_or_after.timestamp())
        return claims
