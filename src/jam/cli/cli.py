# -*- coding: utf-8 -*-

from importlib.metadata import version


try:
    import click
except ImportError:
    from jam.exceptions import JamError

    raise JamError(
        message="To use the Jam CLI, run 'pip install jamlib[cli]'.",
        error_code="jam.cli",
    )

from jam.cli.commands import keychain, keys, password


@click.group()
@click.version_option(version=version("jamlib"))
def cli() -> None:
    """Jam CLI - Key generation and password utilities."""
    pass


cli.add_command(keys.keys)
cli.add_command(keychain.keychain)
cli.add_command(password.password)
