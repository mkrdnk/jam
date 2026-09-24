# -*- coding: utf-8 -*-

import os
from pathlib import Path
import subprocess
import sys
from textwrap import dedent


def test_session_imports_do_not_require_optional_backends():
    """The session package and its base remain usable in a minimal install."""
    source_directory = Path(__file__).resolve().parents[3] / "src"
    environment = os.environ.copy()
    python_path = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        path for path in (str(source_directory), python_path) if path
    )
    script = """
        import sys


        class BlockOptionalBackends:
            def find_spec(self, fullname, path=None, target=None):
                if fullname.split(".", 1)[0] in {"redis", "tinydb"}:
                    raise ModuleNotFoundError(
                        f"optional dependency blocked: {fullname}"
                    )
                return None


        sys.meta_path.insert(0, BlockOptionalBackends())

        import jam.sessions
        import jam.sessions.__base__
        from jam.sessions import BaseSessionModule, REGISTRY

        assert BaseSessionModule is jam.sessions.__base__.BaseSessionModule
        assert set(REGISTRY) == {"redis", "json"}
        assert "jam.sessions.redis" not in sys.modules
        assert "jam.sessions.json" not in sys.modules
    """

    result = subprocess.run(
        [sys.executable, "-c", dedent(script)],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert result.returncode == 0, result.stderr
