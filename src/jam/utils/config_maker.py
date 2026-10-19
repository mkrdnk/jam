# -*- coding: utf-8 -*-

from collections.abc import Callable
import copy
from importlib import import_module
import json
import os
import re
import sys
from typing import Any

from jam.__defaults__ import defaults
from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamConfigurationError
from jam.utils.config_validator import _require_mapping


GENERIC_POINTER = "jam"

CONFIG_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def __yaml_config_parser(
    path: str, pointer: str = GENERIC_POINTER
) -> dict[str, Any]:
    """Private method for parsing YML config with env substitution.

    Supports:
    - ${VAR} - environment variable (required)
    - ${VAR:-default} - environment variable with default value
    - $VAR - short form (required)

    Args:
        path (str): Path to config.yml
        pointer (str): Pointer to config section to read.

    Raises:
        JamConfigurationError: If pyyaml not installed, file not found, or invalid YAML

    Returns:
        dict[str, Any]: Parsed YAML section with environment variable substitution.
    """
    try:
        import yaml
    except ImportError:
        raise JamConfigurationError(
            message="To generate a configuration file from YAML/YML, you need to install PyYaml: "
            "`pip install pyyaml` or `pip install jamlib[yaml]`",
            error_code="configuration.import_error",
        )

    # Pattern to match ${VAR:-default} or ${VAR} or $VAR
    pattern = re.compile(
        r"\$\{([^}^{]+?)(:-([^}]+))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    )

    def replace_env(match):
        if match.group(1):
            var_name = match.group(1)
            default_value = (
                match.group(3) if match.group(3) is not None else None
            )
            env_value = os.getenv(var_name)

            if env_value is None:
                if default_value is not None:
                    return default_value
                raise JamConfigurationError(
                    message=f"Environment variable '{var_name}' not set and no default provided",
                    error_code="configuration.env_var_not_set",
                )
            return env_value
        elif match.group(4):
            var_name = match.group(4)
            env_value = os.getenv(var_name)
            if env_value is None:
                raise JamConfigurationError(
                    message=f"Environment variable '{var_name}' not set",
                    error_code="configuration.env_var_not_set",
                )
            return env_value
        return match.group(0)

    class EnvVarLoader(yaml.SafeLoader):
        pass

    def construct_scalar_with_env(loader, node):
        value = loader.construct_scalar(node)
        # Only process strings that contain variable patterns
        if isinstance(value, str) and pattern.search(value):
            return pattern.sub(replace_env, value)
        return value

    EnvVarLoader.add_constructor(
        "tag:yaml.org,2002:str", construct_scalar_with_env
    )

    try:
        with open(path) as file:
            config = yaml.load(file, Loader=EnvVarLoader)
        if config is None:
            return {}
        _require_mapping(config, "root")
        return config[pointer] if pointer in config else config
    except FileNotFoundError:
        raise JamConfigurationError(
            message=f"YAML config file not found at: {path}",
            error_code="configuration.file_not_found",
        )
    except yaml.YAMLError as e:
        raise JamConfigurationError(
            message=f"Error parsing YAML file: {e}",
            error_code="configuration.yaml_error",
        )


def __toml_config_parser(
    path: str = "pyproject.toml", pointer: str = GENERIC_POINTER
) -> dict[str, Any]:
    """Private method for parsing TOML config with env substitution.

    Supports:
    - ${VAR} - environment variable (required)
    - ${VAR:-default} - environment variable with default value
    - $VAR - short form (required)

    Args:
        path (str): Path to config.toml
        pointer (str): Pointer to config read

    Raises:
       JamConfigurationError: If file not found or invalid TOML file or required env var not set

    Returns:
        (dict[str, Any]): Dict with config param
    """
    if sys.version_info >= (3, 11):
        import tomllib as toml
    else:
        try:
            import toml  # type: ignore
        except ImportError:
            raise JamConfigurationError(
                message="To parse TOML config files, install toml: "
                "`pip install toml` or use Python 3.11+ (built-in tomllib).",
                error_code="configuration.toml_not_installed",
            )

    try:
        if sys.version_info >= (3, 11):
            with open(path, "rb") as file:
                config = toml.load(file)
        else:
            with open(path) as file:
                config = toml.load(file)
    except FileNotFoundError:
        raise JamConfigurationError(
            message=f"TOML config file not found at: {path}",
            error_code="configuration.file_not_found",
        )
    except Exception as e:
        raise JamConfigurationError(
            message=f"Error parsing TOML file: {e}",
            error_code="configuration.toml_error",
        )

    env_pattern = re.compile(
        r"\$\{([^}^{]+?)(:-([^}]+))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    )

    def _env_constructor(value: Any) -> Any:
        """Recursively substitute ${VAR:-default}, ${VAR} and $VAR in strings."""
        if isinstance(value, str):

            def replace_env(match):
                if match.group(1):
                    var_name = match.group(1)
                    default_value = (
                        match.group(3) if match.group(3) is not None else None
                    )
                    env_value = os.getenv(var_name)

                    if env_value is None:
                        if default_value is not None:
                            return default_value
                        raise JamConfigurationError(
                            message=f"Environment variable '{var_name}' not set and no default provided",
                            error_code="configuration.env_var_not_set",
                        )
                    return env_value
                elif match.group(4):
                    var_name = match.group(4)
                    env_value = os.getenv(var_name)
                    if env_value is None:
                        raise JamConfigurationError(
                            message=f"Environment variable '{var_name}' not set",
                            error_code="configuration.env_vat_not_set",
                        )
                    return env_value
                return match.group(0)

            return env_pattern.sub(replace_env, value)
        elif isinstance(value, dict):
            return {k: _env_constructor(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [_env_constructor(v) for v in value]
        else:
            return value

    config = _env_constructor(config)

    if pointer:
        section = config
        for part in pointer.split("."):
            if isinstance(section, dict):
                section = section.get(part, {})
            else:
                return {}
        return section
    return config


def __json_config_parser(
    path: str, encoder: BaseEncoder | type[BaseEncoder] = JsonEncoder
) -> dict[str, Any]:
    """Parse JSON with one-pass environment substitution.

    Quoted and unquoted placeholders are supported. Environment values are
    literal strings, including dollar signs, quotes and control characters.

    Args:
        path: JSON configuration path.
        encoder: JSON decoder.

    Returns:
        Parsed configuration with environment values substituted once.

    Raises:
        JamConfigurationError: The file, JSON or environment is invalid.
    """
    try:
        with open(path) as file:
            content = file.read()
    except FileNotFoundError as exc:
        raise JamConfigurationError(
            message=f"JSON config file not found at: {path}",
            error_code="configuration.file_not_found",
        ) from exc

    pattern = re.compile(
        r"\$\{([^}^{]+?)(:-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    )
    # Quote bare placeholders before decoding; expand only decoded strings.
    quoted_positions: set[int] = set()
    in_string = False
    escaped = False
    for index, char in enumerate(content):
        if in_string:
            quoted_positions.add(index)
        if escaped:
            escaped = False
        elif char == "\\" and in_string:
            escaped = True
        elif char == '"':
            in_string = not in_string
    content = pattern.sub(
        lambda match: (
            match.group(0)
            if match.start() in quoted_positions
            else json.dumps(match.group(0))
        ),
        content,
    )
    try:
        config = encoder.loads(content)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise JamConfigurationError(
            message="Error parsing JSON configuration.",
            error_code="configuration.json_parse_error",
        ) from exc

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(4)
        value = os.getenv(name, match.group(3))
        if value is None:
            raise JamConfigurationError(
                message=f"Environment variable '{name}' not set.",
                error_code="configuration.env_var_not_set",
            )
        return value

    def expand(value: Any) -> Any:
        if isinstance(value, str):
            return pattern.sub(replace, value)
        if isinstance(value, dict):
            return {expand(key): expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [expand(item) for item in value]
        return value

    return _require_mapping(expand(config), "root")


def __config_cache_clear__() -> None:
    """Clear the parsed config cache."""
    CONFIG_CACHE.clear()


def __config_maker__(
    config: str | dict[str, Any], pointer: str = GENERIC_POINTER
) -> dict[str, Any]:
    """Base config masker.

    Args:
        config (str | dict[str, Any): Config dict or file path
        pointer (str): Pointer to config read

    Returns:
        dict[str, Any]: Parsed config
    """
    if isinstance(config, str):
        key = (config, pointer)
        if defaults.CONFIG_CACHING and key in CONFIG_CACHE:
            return copy.deepcopy(CONFIG_CACHE[key])

        ext = config.split(".")[-1].lower()
        match ext:
            case "yml" | "yaml":
                result = __yaml_config_parser(path=config, pointer=pointer)
            case "toml":
                result = __toml_config_parser(path=config, pointer=pointer)
            case "json":
                result = __json_config_parser(path=config)
            case _:
                raise JamConfigurationError(
                    message="YML/YAML, TOML or JSON configs only!",
                    error_code="configuration.invalid_config_type",
                )

        result = _require_mapping(result, pointer or "root").copy()
        if defaults.CONFIG_CACHING:
            CONFIG_CACHE[key] = copy.deepcopy(result)
    else:
        result = _require_mapping(config, "root").copy()

    return result


def __module_loader__(path: str) -> Callable:
    """Loader custom modules from config.

    Args:
        path (str): Path to module. For example: `my_app.classes.SomeClass`

    Raises:
        TypeError: If path not str

    Returns:
        Callable
    """
    if not isinstance(path, str):
        raise TypeError("Path must be a string")
    module_path, class_name = path.rsplit(".", 1)
    module = import_module(module_path)
    return getattr(module, class_name)


def __key_loader__(key: str) -> str:
    """Loads a key from file, if `key` is a path to a file.

    Args:
        key (str): Key to load. If it is a path to a file, the file will be loaded.

    Returns:
        str: Loaded key or original key if not a file path.
    """
    if os.path.isfile(key):
        with open(key) as f:
            return f.read().strip()
    return key
