# -*- coding: utf-8 -*-

"""Async OAuth2 module."""

from typing import Any

from jam.oauth2.__base__ import BaseOAuth2Client
from jam.aio.oauth2.client import OAuth2Client
from jam.aio.oauth2.builtin.github import GitHubOAuth2Client
from jam.aio.oauth2.builtin.gitlab import GitLabOAuth2Client
from jam.aio.oauth2.builtin.google import GoogleOAuth2Client
from jam.aio.oauth2.builtin.yandex import YandexOAuth2Client
from jam.encoders import BaseEncoder, JsonEncoder


BUILTIN_PROVIDERS = {
    "github": "jam.aio.oauth2.builtin.github.GitHubOAuth2Client",
    "gitlab": "jam.aio.oauth2.builtin.gitlab.GitLabOAuth2Client",
    "google": "jam.aio.oauth2.builtin.google.GoogleOAuth2Client",
    "yandex": "jam.aio.oauth2.builtin.yandex.YandexOAuth2Client",
}


def create_instance(
    providers: dict[str, dict],
    serializer: BaseEncoder | type[BaseEncoder] = JsonEncoder,
    **kwargs: Any
) -> dict[str, BaseOAuth2Client]:
    """Create async OAuth2 clients for configured providers.

    Args:
        providers: {provider_name: {client_id, client_secret, redirect_uri, ...}}
        serializer: JSON encoder/decoder
        **kwargs: Additional params

    Returns:
        dict: {provider_name: OAuth2Client instance (async)}
    """
    from jam.utils.config_maker import __module_loader__

    result = {}
    for name, cfg in providers.items():
        cfg = cfg.copy()  # Don't modify original config

        if "custom_module" in cfg:
            module_cls = __module_loader__(cfg.pop("custom_module"))
        else:
            module_path = BUILTIN_PROVIDERS.get(name, "jam.aio.oauth2.client.OAuth2Client")
            module_cls = __module_loader__(module_path)

        # Add serializer to config if not already present
        if "serializer" not in cfg:
            cfg["serializer"] = serializer

        result[name] = module_cls(**cfg)

    return result


__all__ = [
    "BaseOAuth2Client",
    "OAuth2Client",
    "GitHubOAuth2Client",
    "GitLabOAuth2Client",
    "GoogleOAuth2Client",
    "YandexOAuth2Client",
    "create_instance",
]
