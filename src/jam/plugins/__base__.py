# -*- coding: utf-8 -*-

from abc import ABC
from typing import Any


class BasePlugin(ABC):
    """Base plugin for Jam.

    !!! Warning
            Plugins are experimental and may not be stable.

            For usage, JAM_ENABLE_PLUGINS must be set to 1.

    Example:
        ```python
        from jam import Jam
        from jam.plugins import BasePlugin


        class MyPlugin(BasePlugin)
            name = "MyPlugin"

            def on_before_jwt_create(self, **kwargs):
                print("JWT CREATED")

        jam = Jam(
            config="config.toml",
            plugins=[MyPlugin]
        )
        ```
    """

    name: str = "base_plugin"
    jam_requires: str = "3.2.0"
    config: bool = False

    def __init__(self, jam, config: dict | None = None) -> None:
        """Initialize the plugin.

        Args:
            jam (BaseJam): The Jam instance.
            config (dict | None): Plugin configuration.
        """
        self._jam = jam
        self._config = config or {}

    def setup(self) -> None:
        """Called when plugin is initialized."""
        pass

    def emit(self, event: str, **kwargs: Any) -> None:
        """Emit event.

        Args:
            event (str): Event name
            **kwargs: Event data
        """
        self._jam.emit(event, **kwargs)
