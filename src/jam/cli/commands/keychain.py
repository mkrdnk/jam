# -*- coding: utf-8 -*-

"""KeyChain administration commands."""

from typing import Any

import click

from jam import Jam
from jam.keychain import BaseKeyChain


def _chain(config: str | None, name: str) -> BaseKeyChain:
    """Load a named KeyChain through the public Jam configuration path."""
    if config is None:
        raise click.UsageError("Pass the Jam configuration path with --config.")
    chain = Jam(config=config).keychains.get(name)
    if chain is None:
        raise click.ClickException(f"KeyChain '{name}' is not configured.")
    return chain


def _show(info: Any) -> None:
    """Print metadata without exposing key material."""
    click.echo(f"Key ID:       {info.id}")
    click.echo(f"Status:       {info.status}")
    click.echo(f"Created:      {info.created_at.isoformat()}")
    click.echo(f"Algorithm:    {info.algorithm}")
    click.echo(f"Fingerprint:  {info.fingerprint}")


@click.group()
@click.option(
    "--config",
    type=click.Path(exists=True, dir_okay=False),
    help="Jam configuration file containing keychains.",
)
@click.pass_context
def keychain(ctx: click.Context, config: str | None) -> None:
    """Administer configured KeyChains."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@keychain.command()
@click.argument("name")
@click.option("--include-revoked", is_flag=True)
@click.pass_context
def list(ctx: click.Context, name: str, include_revoked: bool) -> None:
    """List key metadata."""
    chain = _chain(ctx.obj["config"], name)
    click.echo("KEY ID\tSTATUS\tCREATED")
    for info in chain.list(include_revoked=include_revoked):
        click.echo(f"{info.id}\t{info.status}\t{info.created_at.isoformat()}")


@keychain.command()
@click.argument("name")
@click.argument("key_id")
@click.pass_context
def show(ctx: click.Context, name: str, key_id: str) -> None:
    """Show metadata for one key."""
    _show(_chain(ctx.obj["config"], name).get(key_id))


@keychain.command()
@click.argument("name")
@click.argument("key_id")
@click.pass_context
def add(ctx: click.Context, name: str, key_id: str) -> None:
    """Generate a standby key."""
    info = _chain(ctx.obj["config"], name).add(key_id)
    click.echo(f"Key {info.id} added successfully.\nStatus: {info.status}")


@keychain.command()
@click.argument("name")
@click.argument("key_id")
@click.pass_context
def activate(ctx: click.Context, name: str, key_id: str) -> None:
    """Make a key current and retire the old current key."""
    _show(_chain(ctx.obj["config"], name).activate(key_id))


@keychain.command()
@click.argument("name")
@click.option("--key-id", help="ID for the generated key.")
@click.pass_context
def rotate(ctx: click.Context, name: str, key_id: str | None) -> None:
    """Generate and activate a new key."""
    _show(_chain(ctx.obj["config"], name).rotate(key_id))


@keychain.command()
@click.argument("name")
@click.argument("key_id")
@click.pass_context
def retire(ctx: click.Context, name: str, key_id: str) -> None:
    """Retire a key while retaining it for verification."""
    _show(_chain(ctx.obj["config"], name).retire(key_id))


@keychain.command()
@click.argument("name")
@click.argument("key_id")
@click.pass_context
def revoke(ctx: click.Context, name: str, key_id: str) -> None:
    """Immediately reject credentials using a compromised key."""
    _show(_chain(ctx.obj["config"], name).revoke(key_id))


@keychain.command()
@click.argument("name")
@click.argument("key_id")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_context
def remove(ctx: click.Context, name: str, key_id: str, yes: bool) -> None:
    """Permanently delete a non-current key."""
    if not yes and not click.confirm(
        f"Remove key '{key_id}' from keychain '{name}'? This cannot be undone."
    ):
        raise click.Abort()
    _chain(ctx.obj["config"], name).remove(key_id)
    click.echo(f"Key {key_id} removed.")


@keychain.command()
@click.argument("name")
@click.pass_context
def current(ctx: click.Context, name: str) -> None:
    """Show the current issuing key."""
    info = _chain(ctx.obj["config"], name).current()
    if info is None:
        raise click.ClickException("KeyChain has no current key.")
    _show(info)
