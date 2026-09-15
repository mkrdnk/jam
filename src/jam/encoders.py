# -*- coding: utf-8 -*-

import json
from typing import Any

from jam.__base_encoder__ import BaseEncoder


class JsonEncoder(BaseEncoder):
    """Json encoder."""

    @classmethod
    def dumps(cls, var: dict[str, Any]) -> bytes:
        """Dump dict."""
        return json.dumps(var, sort_keys=True, separators=(",", ": ")).encode(
            "utf8"
        )

    @classmethod
    def loads(cls, var: str | bytes) -> dict[str, Any]:
        """Load json."""
        return json.loads(var)
