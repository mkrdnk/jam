# -*- coding: utf-8 -*-

from collections.abc import Callable
from importlib import import_module
import os
import re
import sys
from typing import Any

from jam.encoders import BaseEncoder, JsonEncoder
from jam.exceptions import JamConfigurationError


GENERIC_POINTER = "jam"


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
        if not config:
            return {}
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
    """JSON config parser with env substitution.

    Supports:
    - ${VAR} - environment variable (required)
    - ${VAR:-default} - environment variable with default value
    - $VAR - short form (required)

    Args:
        path (str): Path to JSON file
        encoder (BaseEncoder | type[BaseEncoder]): Encoder to use for parsing

    Raises:
        JamConfigurationError: If file not found or invalid JSON or required env var not set

    Returns:
        dict[str, Any]: Parsed config with environment variable substitution
    """
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        raise JamConfigurationError(
            message=f"JSON config file not found at: {path}",
            error_code="configuration.file_not_found",
        )

    env_pattern = re.compile(
        r"\$\{([^}^{]+?)(:-([^}]+))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
    )

    def get_env_value(var_name: str, default_value: str | None) -> str:
        env_value = os.getenv(var_name)
        if env_value is None:
            if default_value is not None:
                return default_value
            raise JamConfigurationError(
                message=f"Environment variable '{var_name}' not set and no default provided",
                error_code="configuration.env_var_not_set",
            )
        return env_value

    def find_string_boundaries(content: str) -> list[tuple[int, int]]:
        boundaries = []
        in_string = False
        escaped = False
        start = -1

        for i, char in enumerate(content):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                if not in_string:
                    start = i
                    in_string = True
                else:
                    boundaries.append((start, i))
                    in_string = False
                    start = -1

        return boundaries

    string_boundaries = find_string_boundaries(content)

    def is_in_string(pos: int) -> bool:
        for start, end in string_boundaries:
            if start < pos < end:
                return True
        return False

    def replace_env_in_content(match):
        var_name = match.group(1) or match.group(4)
        default_value = match.group(3) if match.group(3) is not None else None
        start_pos = match.start()

        in_string = is_in_string(start_pos)
        env_value = get_env_value(var_name, default_value)

        if in_string:
            return env_value.replace("\\", "\\\\").replace('"', '\\"')
        else:
            escaped_value = env_value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped_value}"'

    content = env_pattern.sub(replace_env_in_content, content)

    try:
        config = encoder.loads(content)
    except Exception as e:
        raise JamConfigurationError(
            message=f"Error parsing JSON file: {e}",
            error_code="configuration.json_parse_error",
        ) from e

    def _env_constructor(value: Any) -> Any:
        if isinstance(value, str):

            def replace_env_after(match):
                var_name = match.group(1) or match.group(4)
                default_value = (
                    match.group(3) if match.group(3) is not None else None
                )
                return get_env_value(var_name, default_value)

            if env_pattern.search(value):
                return env_pattern.sub(replace_env_after, value)
        elif isinstance(value, dict):
            return {k: _env_constructor(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [_env_constructor(v) for v in value]
        return value

    config = _env_constructor(config)
    return config


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
        ext = config.split(".")[-1].lower()
        match ext:
            case "yml" | "yaml":
                result = __yaml_config_parser(
                    path=config, pointer=pointer
                ).copy()
            case "toml":
                result = __toml_config_parser(
                    path=config, pointer=pointer
                ).copy()
            case "json":
                result = __json_config_parser(path=config).copy()
            case _:
                raise JamConfigurationError(
                    message="YML/YAML, TOML or JSON configs only!",
                    error_code="configuration.invalid_config_type",
                )
    else:
        result = config.copy()

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
