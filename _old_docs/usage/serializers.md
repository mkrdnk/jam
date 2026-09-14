---
title: JSON serialization
---

Jam makes it easy to replace the JSON serializer in your code; all you need to do is specify a serializer that inherits from `jam.BaseEncoder` in the configuration.


```python
from abc import abstractmethod
import os
from typing import Any

from jam import BaseEncoder, Jam


class SomeEncoder(BaseEncoder):
    @classmethod
    @abstractmethod
    def dumps(cls, var: dict[str, Any]) -> bytes:
        """Dump dict."""
        # some logic

    @classmethod
    @abstractmethod
    def loads(cls, var: str | bytes) -> dict[str, Any]:
        """Load json."""
        # some logic


config = {
    "serializer": SomeEncoder,
    "paseto": {
        "version": "v3",
        "purpose": "local",
        "secret_key": os.getenv("PASETO_SECRET_KEY")
    }
}

jam = Jam(
    config=config,
    # serializer=SomeSerializer  <- Or you can pass it as a parameter to the `jam.Jam` class
)
```
