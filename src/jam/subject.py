# -*- coding: utf-8 -*-

"""Base subject for auth flows."""

from dataclasses import asdict
from typing import Any


class BaseSubject:
    """Base subject contract.

    Subclasses must be dataclasses and declare an ``id`` field::

        @dataclass
        class User(BaseSubject):
            id: str
            name: str

    The ``id`` field is the subject identifier used by ``Jam.issue`` and
    ``Jam.authenticate``. Serialization is built on dataclasses, no extra
    dependencies required.
    """

    id: Any

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate that subclasses declare an ``id`` field.

        Args:
            **kwargs: Additional subclass keyword arguments.
        """
        super().__init_subclass__(**kwargs)
        if "id" not in getattr(cls, "__annotations__", {}):
            raise TypeError(
                f"{cls.__name__} must declare an 'id' field to be a valid subject"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize subject to dict using dataclasses.asdict.

        Returns:
            dict[str, Any]: Subject fields.
        """
        return asdict(self)  # type: ignore[no-matching-overload]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaseSubject":
        """Build a subject instance from a dict.

        Unknown keys are ignored.

        Args:
            data (dict[str, Any]): Subject fields.

        Returns:
            BaseSubject: New subject instance.
        """
        field_names = set(getattr(cls, "__dataclass_fields__", {}))
        return cls(**{k: v for k, v in data.items() if k in field_names})
