# -*- coding: utf-8 -*-

"""Config-driven initialization metaclass.

Classes whose metaclass is `ConfigMeta` accept `config` and `pointer`
keyword arguments in their `__init__`. When `config` is provided, the
metaclass resolves it into a dict via `__config_maker__` and uses the
values as defaults for the matching `__init__` parameters. Explicit
keyword arguments always win over config values.

Example:
    ```python
    class JWT(metaclass=ConfigMeta):
        _CONFIG_POINTER = "jam.jose.jwt"

        def __init__(self, alg=None, secret_key=None, config=None, pointer=None): ...
    ```
"""

from abc import ABCMeta
import inspect
from typing import Any

from jam.utils.config_maker import GENERIC_POINTER, __config_maker__


class ConfigMeta(ABCMeta):
    """Metaclass that injects config values into `__init__` calls."""

    _CONFIG_POINTER: str = GENERIC_POINTER

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        """Create an instance, injecting config values as parameter defaults.

        Args:
            *args: Positional arguments for `__init__`.
            **kwargs: Keyword arguments for `__init__`. The `config` and
                `pointer` keys are consumed by the metaclass.

        Returns:
            Any: A new instance of `cls`.
        """
        config = kwargs.pop("config", None)
        pointer = kwargs.pop("pointer", None)

        if config is None:
            return super().__call__(*args, **kwargs)

        config_data = __config_maker__(
            config, pointer if pointer is not None else cls._CONFIG_POINTER
        )

        signature = inspect.signature(cls.__init__)
        provided = signature.bind_partial(cls, *args, **kwargs).arguments
        provided.pop("self", None)

        call_kwargs: dict[str, Any] = {}
        for name, param in signature.parameters.items():
            if name in ("self", "config", "pointer"):
                continue
            if name in provided:
                if param.kind is inspect.Parameter.VAR_KEYWORD:
                    call_kwargs.update(provided[name])
                else:
                    call_kwargs[name] = provided[name]
            elif name in config_data:
                call_kwargs[name] = config_data[name]

        return super().__call__(**call_kwargs)
