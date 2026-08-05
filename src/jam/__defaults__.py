# -*- coding: utf-8 -*-

from dataclasses import dataclass
import os


@dataclass(slots=True, frozen=True)
class DEFAULTS:
    """Jam defaults vars."""

    DEBUG: bool = os.getenv("JAM_DEBUG", "false").lower() == "true"
    """Debug flag. Use only while developing jam module."""

    TEMP_DIR: str = os.getenv("JAM_TMP_DIR", "/tmp/jam/")
    """tmp directory for storing temporary files and blobs."""

    ENABLE_PLUGINS: bool = os.getenv("JAM_ENABLE_PLUGINS", "1") == "1"
    """Enabling experimental plugin features."""

    CONFIG_CACHING: bool = (
        os.getenv("JAM_CONFIG_CACHING", "true").lower() == "true"
    )
    """Enabling config caching."""


defaults = DEFAULTS()
