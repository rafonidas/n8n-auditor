"""Walk nested JSON structures yielding (json_pointer, key, value) for string leaves."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def walk_strings(data: Any, pointer: str = "") -> Iterator[tuple[str, str, str]]:
    """Yield (json_pointer, last_key, value) for every string leaf under data."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield from walk_strings(value, f"{pointer}/{_escape(str(key))}")
    elif isinstance(data, list):
        for i, value in enumerate(data):
            yield from walk_strings(value, f"{pointer}/{i}")
    elif isinstance(data, str):
        last_key = pointer.rsplit("/", 1)[-1] if "/" in pointer else pointer
        yield pointer, last_key, data
