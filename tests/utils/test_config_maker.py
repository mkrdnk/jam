# -*- coding: utf-8 -*-

import os
import tempfile
from textwrap import dedent

from jam.exceptions import JamConfigurationError
import pytest

from jam.utils.config_maker import (
    __yaml_config_parser as _yaml_parser,
    __toml_config_parser as _toml_parser,
    __config_maker__ as _config_maker,
)


class TestYAMLConfigParser:
    """Test YAML configuration parser with environment variables."""

    @pytest.fixture
    def yaml_config_basic(self):
        """Create a basic YAML config file."""
        content = dedent("""
            jam:
              jose:
                jwt:
                  alg: HS256
                  secret_key: test_secret
              session:
                session_type: json
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def yaml_config_with_env(self):
        """Create a YAML config file with environment variables."""
        content = dedent("""
            jam:
              jose:
                jwt:
                  alg: ${JWT_ALG}
                  secret_key: ${JWT_SECRET}
              session:
                session_type: redis
                redis_uri: redis://${REDIS_HOST}:${REDIS_PORT}/0
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def yaml_config_with_defaults(self):
        """Create a YAML config file with environment variables and defaults."""
        content = dedent("""
            jam:
              jose:
                jwt:
                  alg: ${JWT_ALG:-HS256}
                  secret_key: ${JWT_SECRET}
              session:
                session_type: redis
                redis_uri: redis://${REDIS_HOST:-localhost}:${REDIS_PORT:-6379}/0
              oauth2:
                providers:
                  google:
                    client_id: ${GOOGLE_CLIENT_ID}
                    client_secret: ${GOOGLE_CLIENT_SECRET:-default_secret}
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def yaml_config_with_short_form(self):
        """Create a YAML config file with short form environment variables."""
        content = dedent("""
            jam:
              jose:
                jwt:
                  alg: HS256
                  secret_key: $JWT_SECRET
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    def test_yaml_basic_parsing(self, yaml_config_basic):
        """Test basic YAML parsing without environment variables."""
        config = _yaml_parser(yaml_config_basic)
        assert config["jose"]["jwt"]["alg"] == "HS256"
        assert config["jose"]["jwt"]["secret_key"] == "test_secret"
        assert config["session"]["session_type"] == "json"

    def test_yaml_env_substitution(self, yaml_config_with_env):
        """Test environment variable substitution in YAML."""
        os.environ["JWT_ALG"] = "HS512"
        os.environ["JWT_SECRET"] = "super_secret"
        os.environ["REDIS_HOST"] = "redis.example.com"
        os.environ["REDIS_PORT"] = "6380"

        try:
            config = _yaml_parser(yaml_config_with_env)
            assert config["jose"]["jwt"]["alg"] == "HS512"
            assert config["jose"]["jwt"]["secret_key"] == "super_secret"
            assert (
                config["session"]["redis_uri"]
                == "redis://redis.example.com:6380/0"
            )
        finally:
            del os.environ["JWT_ALG"]
            del os.environ["JWT_SECRET"]
            del os.environ["REDIS_HOST"]
            del os.environ["REDIS_PORT"]

    def test_yaml_env_with_defaults(self, yaml_config_with_defaults):
        """Test environment variables with default values in YAML."""
        os.environ["JWT_SECRET"] = "my_secret"
        os.environ["GOOGLE_CLIENT_ID"] = "google_id_123"

        try:
            config = _yaml_parser(yaml_config_with_defaults)
            assert config["jose"]["jwt"]["alg"] == "HS256"
            assert config["jose"]["jwt"]["secret_key"] == "my_secret"
            assert config["session"]["redis_uri"] == "redis://localhost:6379/0"
            assert (
                config["oauth2"]["providers"]["google"]["client_id"]
                == "google_id_123"
            )
            assert (
                config["oauth2"]["providers"]["google"]["client_secret"]
                == "default_secret"
            )
        finally:
            del os.environ["JWT_SECRET"]
            del os.environ["GOOGLE_CLIENT_ID"]

    def test_yaml_missing_required_env(self, yaml_config_with_env):
        """Test that missing required environment variable raises error."""
        for var in ["JWT_ALG", "JWT_SECRET", "REDIS_HOST", "REDIS_PORT"]:
            os.environ.pop(var, None)

        with pytest.raises(JamConfigurationError):
            _yaml_parser(yaml_config_with_env)

    def test_yaml_short_form(self, yaml_config_with_short_form):
        """Test short form environment variable substitution ($VAR)."""
        os.environ["JWT_SECRET"] = "short_secret"

        try:
            config = _yaml_parser(yaml_config_with_short_form)
            assert config["jose"]["jwt"]["secret_key"] == "short_secret"
        finally:
            del os.environ["JWT_SECRET"]

    def test_yaml_file_not_found(self):
        """Test that missing file raises FileNotFoundError."""
        with pytest.raises(JamConfigurationError):
            _yaml_parser("nonexistent.yml")


class TestTOMLConfigParser:
    """Test TOML configuration parser with environment variables."""

    @pytest.fixture
    def toml_config_basic(self):
        """Create a basic TOML config file."""
        content = dedent("""
            [jam.jose.jwt]
            alg = "HS256"
            secret_key = "test_secret"

            [jam.session]
            session_type = "json"
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def toml_config_with_env(self):
        """Create a TOML config file with environment variables."""
        content = dedent("""
            [jam.jose.jwt]
            alg = "${JWT_ALG}"
            secret_key = "${JWT_SECRET}"

            [jam.session]
            session_type = "redis"
            redis_uri = "redis://${REDIS_HOST}:${REDIS_PORT}/0"
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def toml_config_with_defaults(self):
        """Create a TOML config file with environment variables and defaults."""
        content = dedent("""
            [jam.jose.jwt]
            alg = "${JWT_ALG:-HS256}"
            secret_key = "${JWT_SECRET}"

            [jam.session]
            session_type = "redis"
            redis_uri = "redis://${REDIS_HOST:-localhost}:${REDIS_PORT:-6379}/0"

            [jam.oauth2.providers.google]
            client_id = "${GOOGLE_CLIENT_ID}"
            client_secret = "${GOOGLE_CLIENT_SECRET:-default_secret}"
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def toml_config_with_short_form(self):
        """Create a TOML config file with short form environment variables."""
        content = dedent("""
            [jam.jose.jwt]
            alg = "HS256"
            secret_key = "$JWT_SECRET"
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def toml_config_with_list(self):
        """Create a TOML config file with list containing environment variables."""
        content = dedent("""
            [jam.jose.jwt]
            allowed_algorithms = ["HS256", "${EXTRA_ALG:-RS256}"]
            secret_key = "${JWT_SECRET}"
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    def test_toml_basic_parsing(self, toml_config_basic):
        """Test basic TOML parsing without environment variables."""
        config = _toml_parser(toml_config_basic)
        assert config["jose"]["jwt"]["alg"] == "HS256"
        assert config["jose"]["jwt"]["secret_key"] == "test_secret"
        assert config["session"]["session_type"] == "json"

    def test_toml_env_substitution(self, toml_config_with_env):
        """Test environment variable substitution in TOML."""
        os.environ["JWT_ALG"] = "HS512"
        os.environ["JWT_SECRET"] = "super_secret"
        os.environ["REDIS_HOST"] = "redis.example.com"
        os.environ["REDIS_PORT"] = "6380"

        try:
            config = _toml_parser(toml_config_with_env)
            assert config["jose"]["jwt"]["alg"] == "HS512"
            assert config["jose"]["jwt"]["secret_key"] == "super_secret"
            assert (
                config["session"]["redis_uri"]
                == "redis://redis.example.com:6380/0"
            )
        finally:
            del os.environ["JWT_ALG"]
            del os.environ["JWT_SECRET"]
            del os.environ["REDIS_HOST"]
            del os.environ["REDIS_PORT"]

    def test_toml_env_with_defaults(self, toml_config_with_defaults):
        """Test environment variables with default values in TOML."""
        os.environ["JWT_SECRET"] = "my_secret"
        os.environ["GOOGLE_CLIENT_ID"] = "google_id_123"

        try:
            config = _toml_parser(toml_config_with_defaults)
            assert config["jose"]["jwt"]["alg"] == "HS256"
            assert config["jose"]["jwt"]["secret_key"] == "my_secret"
            assert config["session"]["redis_uri"] == "redis://localhost:6379/0"
            assert (
                config["oauth2"]["providers"]["google"]["client_id"]
                == "google_id_123"
            )
            assert (
                config["oauth2"]["providers"]["google"]["client_secret"]
                == "default_secret"
            )
        finally:
            del os.environ["JWT_SECRET"]
            del os.environ["GOOGLE_CLIENT_ID"]

    def test_toml_missing_required_env(self, toml_config_with_env):
        """Test that missing required environment variable raises error."""
        for var in ["JWT_ALG", "JWT_SECRET", "REDIS_HOST", "REDIS_PORT"]:
            os.environ.pop(var, None)

        with pytest.raises(JamConfigurationError):
            _toml_parser(toml_config_with_env)

    def test_toml_short_form(self, toml_config_with_short_form):
        """Test short form environment variable substitution ($VAR)."""
        os.environ["JWT_SECRET"] = "short_secret"

        try:
            config = _toml_parser(toml_config_with_short_form)
            assert config["jose"]["jwt"]["secret_key"] == "short_secret"
        finally:
            del os.environ["JWT_SECRET"]

    def test_toml_with_list(self, toml_config_with_list):
        """Test environment variables in lists."""
        os.environ["JWT_SECRET"] = "list_secret"
        os.environ["EXTRA_ALG"] = "ES256"

        try:
            config = _toml_parser(toml_config_with_list)
            assert config["jose"]["jwt"]["allowed_algorithms"] == [
                "HS256",
                "ES256",
            ]
            assert config["jose"]["jwt"]["secret_key"] == "list_secret"
        finally:
            del os.environ["JWT_SECRET"]
            del os.environ["EXTRA_ALG"]

    def test_toml_with_list_default(self, toml_config_with_list):
        """Test environment variables in lists with defaults."""
        os.environ["JWT_SECRET"] = "list_secret"

        try:
            config = _toml_parser(toml_config_with_list)
            assert config["jose"]["jwt"]["allowed_algorithms"] == [
                "HS256",
                "RS256",
            ]
        finally:
            del os.environ["JWT_SECRET"]

    def test_toml_file_not_found(self):
        """Test that missing file raises FileNotFoundError."""
        with pytest.raises(JamConfigurationError):
            _toml_parser("nonexistent.toml")


class TestConfigMaker:
    """Test the main config maker function."""

    @pytest.fixture
    def yaml_config_file(self):
        """Create a YAML config file."""
        content = dedent("""
            jam:
              jose:
                jwt:
                  alg: ${JWT_ALG:-HS256}
                  secret_key: ${JWT_SECRET}
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    @pytest.fixture
    def toml_config_file(self):
        """Create a TOML config file."""
        content = dedent("""
            [jam.jose.jwt]
            alg = "${JWT_ALG:-HS256}"
            secret_key = "${JWT_SECRET}"
        """).strip()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            fname = f.name
        yield fname
        os.unlink(fname)

    def test_config_maker_with_dict(self):
        """Test config maker with dictionary input."""
        config_dict = {
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "test_secret",
                }
            }
        }
        result = _config_maker(config_dict)
        assert result["jose"]["jwt"]["alg"] == "HS256"
        assert result["jose"]["jwt"]["secret_key"] == "test_secret"
        assert result is not config_dict

    def test_config_maker_with_yaml(self, yaml_config_file):
        """Test config maker with YAML file."""
        os.environ["JWT_SECRET"] = "yaml_secret"

        try:
            config = _config_maker(yaml_config_file)
            assert config["jose"]["jwt"]["alg"] == "HS256"
            assert config["jose"]["jwt"]["secret_key"] == "yaml_secret"
        finally:
            del os.environ["JWT_SECRET"]

    def test_config_maker_with_toml(self, toml_config_file):
        """Test config maker with TOML file."""
        os.environ["JWT_SECRET"] = "toml_secret"

        try:
            config = _config_maker(toml_config_file)
            assert config["jose"]["jwt"]["alg"] == "HS256"
            assert config["jose"]["jwt"]["secret_key"] == "toml_secret"
        finally:
            del os.environ["JWT_SECRET"]

    def test_config_maker_unsupported_format(self):
        """Test that unsupported config format raises error."""
        with pytest.raises(JamConfigurationError):
            _config_maker("config.json")
