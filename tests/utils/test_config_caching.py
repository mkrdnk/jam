# -*- coding: utf-8 -*-

from textwrap import dedent

import pytest

from jam.__defaults__ import DEFAULTS
import jam.utils.config_maker as config_maker
from jam.utils.config_maker import __config_cache_clear__, __config_maker__


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the module-level cache before and after each test."""
    __config_cache_clear__()
    yield
    __config_cache_clear__()


@pytest.fixture
def yaml_config_file(tmp_path):
    """Create a YAML config file with a mutable alg value."""
    path = tmp_path / "config.yml"
    path.write_text(
        dedent(
            """
            jam:
              jose:
                jwt:
                  alg: HS256
                  secret_key: test_secret
            """
        ).strip()
    )
    return str(path)


@pytest.fixture
def toml_config_file(tmp_path):
    """Create a TOML config file with a mutable alg value."""
    path = tmp_path / "config.toml"
    path.write_text(
        dedent(
            """
            [jam.jose.jwt]
            alg = "HS256"
            secret_key = "test_secret"
            """
        ).strip()
    )
    return str(path)


def rewrite_yaml(path: str, alg: str) -> None:
    """Rewrite the YAML config file with a new alg value."""
    with open(path, "w") as f:
        f.write(
            dedent(
                f"""
                jam:
                  jose:
                    jwt:
                      alg: {alg}
                      secret_key: test_secret
                """
            ).strip()
        )


class TestConfigCaching:
    """Test config caching via JAM_CONFIG_CACHING."""

    def test_caching_on_reuses_parsed_config(self, yaml_config_file):
        """With caching enabled the file is parsed once."""
        first = __config_maker__(yaml_config_file)
        assert first["jose"]["jwt"]["alg"] == "HS256"

        rewrite_yaml(yaml_config_file, "HS512")
        second = __config_maker__(yaml_config_file)

        assert second["jose"]["jwt"]["alg"] == "HS256"

    def test_caching_off_rereads_config(self, yaml_config_file, monkeypatch):
        """With caching disabled the file is re-read each call."""
        monkeypatch.setattr(
            config_maker, "defaults", DEFAULTS(CONFIG_CACHING=False)
        )

        first = __config_maker__(yaml_config_file)
        assert first["jose"]["jwt"]["alg"] == "HS256"

        rewrite_yaml(yaml_config_file, "HS512")
        second = __config_maker__(yaml_config_file)

        assert second["jose"]["jwt"]["alg"] == "HS512"

    def test_cache_returns_independent_copies(self, yaml_config_file):
        """Mutating the returned config must not corrupt the cache."""
        first = __config_maker__(yaml_config_file)
        first["jose"]["jwt"]["alg"] = "RS256"

        second = __config_maker__(yaml_config_file)

        assert second["jose"]["jwt"]["alg"] == "HS256"

    def test_cache_clear_rereads_file(self, yaml_config_file):
        """Clearing the cache forces a fresh read on the next call."""
        __config_maker__(yaml_config_file)

        rewrite_yaml(yaml_config_file, "HS512")
        __config_cache_clear__()
        fresh = __config_maker__(yaml_config_file)

        assert fresh["jose"]["jwt"]["alg"] == "HS512"

    def test_cache_keyed_by_pointer(self, tmp_path):
        """Different pointers on the same file get separate cache entries."""
        path = tmp_path / "config.yml"
        path.write_text(
            dedent(
                """
                jam:
                  jose:
                    jwt:
                      alg: HS256
                app:
                  level: info
                """
            ).strip()
        )
        str_path = str(path)

        jam_cfg = __config_maker__(str_path, pointer="jam")
        app_cfg = __config_maker__(str_path, pointer="app")

        assert jam_cfg["jose"]["jwt"]["alg"] == "HS256"
        assert "jose" not in app_cfg
        assert app_cfg["level"] == "info"

    def test_toml_caching_on_reuses_parsed_config(self, toml_config_file):
        """TOML configs are cached the same way."""
        first = __config_maker__(toml_config_file)
        assert first["jose"]["jwt"]["alg"] == "HS256"

        with open(toml_config_file, "w") as f:
            f.write(
                dedent(
                    """
                    [jam.jose.jwt]
                    alg = "ES256"
                    secret_key = "test_secret"
                    """
                ).strip()
            )

        second = __config_maker__(toml_config_file)
        assert second["jose"]["jwt"]["alg"] == "HS256"

    def test_errors_are_not_cached(self, tmp_path):
        """A failed parse must not leave a stale entry in the cache."""
        path = tmp_path / "config.yml"
        str_path = str(path)

        with pytest.raises(Exception):
            __config_maker__(str_path)

        path.write_text(
            dedent(
                """
                jam:
                  jose:
                    jwt:
                      alg: HS256
                """
            ).strip()
        )
        config = __config_maker__(str_path)
        assert config["jose"]["jwt"]["alg"] == "HS256"
