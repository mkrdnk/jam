# -*- coding: utf-8 -*-

from importlib.metadata import version

from click.testing import CliRunner
import pytest

from jam.cli import cli


def test_cli_help_and_version():
    runner = CliRunner()

    help_result = runner.invoke(cli, ["--help"])
    version_result = runner.invoke(cli, ["--version"])

    assert help_result.exit_code == 0
    assert "Key generation and password utilities" in help_result.output
    assert version_result.exit_code == 0
    assert version("jamlib") in version_result.output


@pytest.mark.parametrize(
    ("command", "arguments", "outputs"),
    [
        (
            "rsa",
            [
                "--private-out",
                "rsa-private.pem",
                "--public-out",
                "rsa-public.pem",
            ],
            ["rsa-private.pem", "rsa-public.pem"],
        ),
        (
            "ed25519",
            [
                "--private-out",
                "ed-private.pem",
                "--public-out",
                "ed-public.pem",
            ],
            ["ed-private.pem", "ed-public.pem"],
        ),
        (
            "ecdsa",
            [
                "--private-out",
                "ec-private.pem",
                "--public-out",
                "ec-public.pem",
            ],
            ["ec-private.pem", "ec-public.pem"],
        ),
        ("aes", ["--out", "aes.key"], ["aes.key"]),
        (
            "symmetric",
            ["--out", "symmetric.key", "--bytes", "16"],
            ["symmetric.key"],
        ),
    ],
)
def test_key_generation_commands(command, arguments, outputs, tmp_path):
    runner = CliRunner()
    output_paths = {output: tmp_path / output for output in outputs}
    resolved_arguments = [
        str(output_paths.get(argument, argument)) for argument in arguments
    ]

    result = runner.invoke(cli, ["keys", command, *resolved_arguments])

    assert result.exit_code == 0, result.output
    for output in outputs:
        assert output_paths[output].read_bytes()


def test_password_hash_and_verify_commands():
    runner = CliRunner()

    hashed = runner.invoke(cli, ["password", "hash", "correct horse"])

    assert hashed.exit_code == 0
    serialized = hashed.output.strip()
    assert "$" in serialized

    matching = runner.invoke(
        cli,
        ["password", "verify", "--hash", serialized],
        input="correct horse\n",
    )
    mismatching = runner.invoke(
        cli,
        ["password", "verify", "--hash", serialized],
        input="wrong battery\n",
    )

    assert matching.exit_code == 0
    assert "Password matches" in matching.output
    assert mismatching.exit_code == 1
    assert "Password does not match" in mismatching.output


def test_password_hash_can_be_written_to_file(tmp_path):
    runner = CliRunner()
    output = tmp_path / "password.hash"

    result = runner.invoke(
        cli,
        ["password", "hash", "secret", "--out", str(output)],
    )

    assert result.exit_code == 0
    assert "$" in output.read_text()
