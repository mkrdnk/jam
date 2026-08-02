# -*- coding: utf-8 -*-

"""Base subject for auth flows."""

from dataclasses import asdict
from typing import Any, ClassVar


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

    id: ClassVar[Any]
    __abstract_methods__: ClassVar[bool] = True

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

        Args:
            data (dict[str, Any]): Subject fields.

        Returns:
            BaseSubject: New subject instance.
        """
        return cls(**data)
