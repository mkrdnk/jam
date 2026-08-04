# -*- coding: utf-8 -*-

from __future__ import annotations

from abc import ABC, abstractmethod
import dataclasses
import logging
from typing import Any, cast

from jam.__base_encoder__ import BaseEncoder
from jam.authz import BasePolicy, Policy
from jam.encoders import JsonEncoder
from jam.exceptions import JamConfigurationError
from jam.plugins.__base__ import BasePlugin
from jam.subject import BaseSubject
from jam.utils.config_maker import __config_maker__, __module_loader__


logger = logging.getLogger(__name__)


class BaseJam(ABC):
    """Base jam instance."""

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
    _policy: BasePolicy | None = None

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
        self._policy: BasePolicy | None = None

        logger.debug("Initializing BaseJam with serializer=%s", serializer)
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
        from jam.oauth2 import build_clients
        from jam.paseto import REGISTRY as PASETO_REGISTRY
        from jam.sessions import REGISTRY as SESSION_REGISTRY

        jose_cfg = config.get("jose") or {}
        if not isinstance(jose_cfg, dict):
            jose_cfg = {}
        self.jose = {}

        jwt_cfg = jose_cfg.get("jwt")
        if jwt_cfg is not None:
            self.jwt = JWT(config=jwt_cfg)
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
            if session_type not in SESSION_REGISTRY:
                raise JamConfigurationError(
                    message=(
                        f"Unknown session type: {session_type}. "
                        f"Available: {list(SESSION_REGISTRY)}"
                    ),
                    error_code="configuration.session.unknown_type",
                )
            module_cls = SESSION_REGISTRY[session_type]
            self.session = module_cls(config=cfg, session_type=session_type)

        oauth2_cfg = config.get("oauth2")
        if isinstance(oauth2_cfg, dict) and oauth2_cfg:
            self.oauth2 = build_clients(oauth2_cfg, serializer=self._serializer)

        paseto_cfg = config.get("paseto")
        if isinstance(paseto_cfg, dict):
            cfg = paseto_cfg.copy()
            version = cfg.pop("version", None)
            if version not in PASETO_REGISTRY:
                raise JamConfigurationError(
                    message=(
                        f"Unknown PASETO version: {version}. "
                        f"Available: {list(PASETO_REGISTRY)}"
                    ),
                    error_code="configuration.paseto.unknown_version",
                )
            module_cls = PASETO_REGISTRY[version]
            self.paseto = module_cls(config=cfg)

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
        if not dataclasses.is_dataclass(self.subject):
            return payload
        field_names = {f.name for f in dataclasses.fields(self.subject)}
        data = {k: v for k, v in payload.items() if k in field_names}
        return self.subject.from_dict(data)

    @abstractmethod
    def authorize(self, subject: BaseSubject, permission: str) -> bool:
        """Check whether a subject is allowed to perform a permission.

        Args:
            subject (BaseSubject): Subject instance.
            permission (str): Permission name.

        Returns:
            bool: True if allowed, False otherwise.
        """
        raise NotImplementedError

    @abstractmethod
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
            subject (BaseSubject): Subject instance.
            via (str | None): Token type: "jwt", "paseto", "session" or None
                for auto-detect.
            exp (int | None): Expiration in seconds.
            iss (str | None): Issuer.
            aud (str | None): Audience.
            nbf (int | None): Not-before in seconds.
            jti (str | None): Token ID.
            **claims: Extra payload claims.

        Returns:
            str: Issued token or session ID.
        """
        raise NotImplementedError

    @abstractmethod
    def authenticate(
        self, token: str, via: str | None = None
    ) -> BaseSubject | dict[str, Any]:
        """Authenticate a token or session and return a subject.

        Args:
            token (str): Token or session ID.
            via (str | None): Token type: "jwt", "paseto", "session" or None
                for auto-detect.

        Returns:
            BaseSubject | dict[str, Any]: Subject instance or raw payload dict.
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
