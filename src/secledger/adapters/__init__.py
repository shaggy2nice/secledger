"""Example scanner adapters: native scanner JSON -> secledger findings schema.

Each adapter exposes ``convert(raw, *, run_id=None, target="") -> dict``.
Register a new one by adding it to ``ADAPTERS``. These ship as working
examples — copy the closest one for your scanner.
"""
from __future__ import annotations

from typing import Any, Callable

from . import semgrep, trivy, zap

ConvertFn = Callable[..., dict]

ADAPTERS: dict[str, ConvertFn] = {
    "semgrep": semgrep.convert,
    "trivy": trivy.convert,
    "zap": zap.convert,
}


def get_adapter(name: str) -> ConvertFn:
    try:
        return ADAPTERS[name]
    except KeyError:
        raise KeyError(
            f"unknown adapter {name!r}; available: {', '.join(sorted(ADAPTERS))}"
        )


def available() -> list[str]:
    return sorted(ADAPTERS)


__all__ = ["ADAPTERS", "get_adapter", "available"]
