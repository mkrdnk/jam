# -*- coding: utf-8 -*-

from __future__ import annotations

from abc import ABC, abstractmethod
import dataclasses
import logging
import re
import time
from typing import Any, cast

from jam.__base_encoder__ import BaseEncoder
from jam.authz import (
    AuthorizationContext,
    BasePolicy,
    Policy,
    Principal,
)
from jam.encoders import JsonEncoder
from jam.exceptions import JamConfigurationError
from jam.plugins.__base__ import BasePlugin
from jam.subject import BaseSubject
from jam.utils.config_maker import __config_maker__, __module_loader__


logger = logging.getLogger(__name__)


class _JamCore:
    """Configuration and pure operations shared by sync and async facades."""

    _async = False

    subject: type[BaseSubject] = BaseSubject
    config: dict[str, Any] | None = None

    jwt: Any = None
    jws: Any = None
    jwe: Any = None
    jose: dict[str, Any] | None = None
    session: Any = None
    oauth2: dict[str, Any] | None = None
    otp: Any = None
    paseto: Any = None
    keychains: dict[str, Any]
    _jwt_list: Any = None
    _policy: BasePolicy

    def __init__(
        self,
        config: str | dict[str, Any] | None = None,
        pointer: str = "jam",
        *,
        serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
        subject: type[BaseSubject] | None = None,
        plugins: list[type[BasePlugin]] | None = None,
    ) -> None:
        """Initialize instance.

        Args:
            config (Union[str, dict[str, Any], None]): Configuration dict or
                file path. Defaults to the class attribute.
            pointer (str): Config pointer. Defaults to "jam".
            serializer (Union[BaseEncoder, type[BaseEncoder]]): Serializer.
            subject (type[BaseSubject] | None): Subject class override.
            plugins (list[type[BasePlugin]] | None): List of plugins.
        """
        if config is None:
            config = self.config or {}
        config = __config_maker__(config, pointer)
        serializer = self.__build_main_config(config, serializer)

        self.config = config
        self._serializer = serializer
        self._plugins = []

        if subject is not None:
            self.subject = subject

        self.jwt = None
        self.jws = None
        self.jwe = None
        self.jose: dict[str, Any] | None = None
        self.session = None
        self.oauth2: dict[str, Any] | None = None
        self.otp = None
        self.paseto = None
        self.keychains = {}
        self._jwt_list = None
        self._policy: BasePolicy = Policy()

        logger.debug(
            "Initializing %s with serializer=%s",
            type(self).__name__,
            serializer,
        )
        self.__build_instance(config)
        logger.debug(
            "BaseJam initialization complete. Modules loaded:\n"
            " jwt=%s, jws=%s, jwe=%s, session=%s, oauth2=%s, paseto=%s, otp=%s",
            self.jwt is not None,
            self.jws is not None,
            self.jwe is not None,
            self.session is not None,
            self.oauth2 is not None,
            self.paseto is not None,
            self.otp is not None,
        )

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
        from jam.jose import JWE, JWS, JWT
        from jam.paseto import REGISTRY as PASETO_REGISTRY

        jose_cfg = config.get("jose") or {}
        if not isinstance(jose_cfg, dict):
            jose_cfg = {}
        self.jose = {}
        keychain_cfg = config.get("keychains") or {}

        def get_keychain(name: str, algorithm: str, purpose: str | None = None) -> Any:
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

        jwt_cfg = jose_cfg.get("jwt")
        if jwt_cfg is not None:
            jwt_cfg = jwt_cfg.copy()
            chain_name = jwt_cfg.pop("keychain", None)
            if self._async:
                jwt_cfg = jwt_cfg.copy()
                list_cfg = jwt_cfg.pop("list", None)
                if list_cfg is not None:
                    from jam.aio.lists import build_list

                    self._jwt_list = build_list(list_cfg)
            self.jwt = JWT(
                config=jwt_cfg,
                keychain=(
                    get_keychain(chain_name, jwt_cfg.get("alg", "HS256"))
                    if chain_name
                    else None
                ),
            )
            self.jose["jwt"] = self.jwt

        jws_cfg = jose_cfg.get("jws")
        if jws_cfg is not None:
            self.jws = JWS(config=jws_cfg)
            self.jose["jws"] = self.jws

        jwe_cfg = jose_cfg.get("jwe")
        if jwe_cfg is not None:
            self.jwe = JWE(config=jwe_cfg)
            self.jose["jwe"] = self.jwe

        if not self.jose:
            self.jose = None

        session_cfg = config.get("session")
        if isinstance(session_cfg, dict):
            cfg = session_cfg.copy()
            session_type = cfg.pop("type", None)
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
                    serializer=self._serializer,
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
            cfg = paseto_cfg.copy()
            version = cfg.pop("version", None)
            chain_name = cfg.pop("keychain", None)
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

        for chain_name, chain_config in keychain_cfg.items():
            if isinstance(chain_config, dict) and chain_name not in self.keychains:
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
    def _detect_token_type(token: str) -> str:
        """Detect a credential type from its serialized format."""
        if re.match(r"^v[1-4]\.(local|public)\.", token):
            return "paseto"
        if token.count(".") == 4:
            return "jwe"
        if token.count(".") == 2:
            return "jwt"
        return "session"

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


class BaseJam(_JamCore, ABC):
    """Base synchronous Jam instance."""

    @abstractmethod
    def authorize(
        self,
        principal: Principal[Any] | BaseSubject | dict[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Check whether a subject is allowed to perform a permission.

        Args:
            principal: Authenticated principal, subject or subject mapping.
            permission (str): Permission name.
            context: Dynamic authorization context.

        Returns:
            bool: True if allowed, False otherwise.
        """
        raise NotImplementedError

    @abstractmethod
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
            subject (BaseSubject): Subject instance.
            via (str | None): Token type: "jwt", "paseto", "session" or None
                for auto-detect.
            exp (int | None): Expiration in seconds.
            iss (str | None): Issuer.
            aud (str | None): Audience.
            nbf (int | None): Not-before in seconds.
            jti (str | None): Token ID.
            permissions: Permissions granted to this credential.
            **claims: Extra payload claims.

        Returns:
            str: Issued token or session ID.
        """
        raise NotImplementedError

    @abstractmethod
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
        """
        raise NotImplementedError

    def emit(self, event: str, **kwargs: Any) -> dict[str, Any]:
        """Emit event.

        Args:
            event (str): Event name,
            **kwargs: Event data

        Returns:
            dict[str, Any]: Updated event data.
        """
        for plugin in self._plugins:
            handler = getattr(plugin, f"on_{event}", None)

            if handler:
                try:
                    result = handler(**kwargs)
                    if isinstance(result, dict):
                        kwargs.update(result)

                except Exception as e:
                    logger.error("Plugin: %s | error: %s", plugin.name, e)

        return kwargs
