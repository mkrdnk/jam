# -*- coding: utf-8 -*-

"""Django application configuration for Jam."""

from django.apps import AppConfig

from jam.ext.django.runtime import get_jam


class JamDjangoConfig(AppConfig):
    """Initialize and validate the configured Jam instance at startup."""

    name = "jam.ext.django"
    verbose_name = "Jam"
    default = True

    def ready(self) -> None:
        """Fail early when ``JAM_CONFIG`` cannot create a Jam instance."""
        get_jam()
