# -*- coding: utf-8 -*-

"""OAuth2 module."""

import inspect
from typing import Any

from .__base__ import BaseOAuth2Client
from .builtin.github import GitHubOAuth2Client
from .builtin.gitlab import GitLabOAuth2Client
from .builtin.google import GoogleOAuth2Client
from .builtin.yandex import YandexOAuth2Client
from jam.encoders import BaseEncoder, JsonEncoder


BUILTIN_PROVIDERS = {
    "github": "jam.oauth2.builtin.github.GitHubOAuth2Client",
    "gitlab": "jam.oauth2.builtin.gitlab.GitLabOAuth2Client",
    "google": "jam.oauth2.builtin.google.GoogleOAuth2Client",
    "yandex": "jam.oauth2.builtin.yandex.YandexOAuth2Client",
}


def build_clients(
    providers: dict[str, dict[str, Any]],
    serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
) -> dict[str, BaseOAuth2Client]:
    """Build OAuth2 clients for the configured providers.

    Args:
        providers (dict[str, dict[str, Any]]): Mapping of provider name to its
            config dict, e.g. ``{"github": {"client_id": "...", "client_secret":
            "...", "redirect_url": "..."}}``. A ``custom_module`` key selects a
            custom client class.
        serializer (BaseEncoder | type[BaseEncoder]): JSON encoder/decoder.

    Returns:
        dict[str, BaseOAuth2Client]: Mapping of provider name to client instance.
    """
    from jam.utils.config_maker import __module_loader__

    result: dict[str, BaseOAuth2Client] = {}
    for name, cfg in providers.items():
        cfg = cfg.copy()  # Don't modify original config

        if "custom_module" in cfg:
            module_cls = __module_loader__(cfg.pop("custom_module"))
        else:
            module_path = BUILTIN_PROVIDERS.get(
                name, "jam.oauth2.client.OAuth2Client"
            )
            module_cls = __module_loader__(module_path)

        # Add serializer to config if the client accepts it
        if (
            "serializer" not in cfg
            and "serializer" in inspect.signature(module_cls.__init__).parameters
        ):
            cfg["serializer"] = serializer

        result[name] = module_cls(**cfg)

    return result


__all__ = [
    "BaseOAuth2Client",
    "GitHubOAuth2Client",
    "GitLabOAuth2Client",
    "GoogleOAuth2Client",
    "YandexOAuth2Client",
    "build_clients",
]
