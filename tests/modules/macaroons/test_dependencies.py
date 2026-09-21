"""Macaroons must not import third-party reference implementations."""

import subprocess
import sys
import textwrap


def test_third_party_flow_without_nacl_or_packaging():
    program = textwrap.dedent(
        """
        import importlib.abc
        import sys

        class RejectOptionalDependencies(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".")[0] in {
                    "nacl", "pymacaroons", "packaging", "tinydb", "redis",
                }:
                    raise AssertionError(f"Unexpected dependency: {fullname}")
                return None

        sys.meta_path.insert(0, RejectOptionalDependencies())

        from jam import Jam
        from jam.macaroons import Caveat, Macaroon

        jam = Jam({
            "keychains": {"root": {"type": "Memory"}},
            "macaroon": {"keychain": "root"},
        })
        jam.keychains["root"].rotate("first")
        token = jam.issue(
            {"id": "alice"}, via="macaroon", permissions=["documents:*"],
        )
        primary = jam.macaroon.decode(token).add_third_party_caveat(
            b"third-party-secret", b"approval",
        )
        discharge = Macaroon.create_discharge(
            b"third-party-secret", b"approval",
        ).add_caveat(Caveat("permission", "documents:read")).bind(primary)
        principal = jam.authenticate(
            primary.encode(), via="macaroon", discharges=[discharge.encode()],
        )
        assert jam.authorize(principal, "documents:read")
        assert not jam.authorize(principal, "documents:write")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
