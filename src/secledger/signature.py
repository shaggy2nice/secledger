"""Deterministic dedup signatures.

A *signature* is the stable key that decides whether two findings — possibly
from different runs, different scanners, or worded slightly differently — are
"the same issue" for ledger purposes.

The default strategy is intentionally simple and transparent:

* If the scanner supplied a ``fingerprint``, trust it: ``fp::<fingerprint>``.
  This is exact, not heuristic, and is the recommended path for scanners that
  emit stable fingerprints (Semgrep, CodeQL, many SAST tools).
* Otherwise key on ``category :: normalized(location)``.

Normalization folds away the incidental differences that would otherwise
split one issue into many: scheme+host, query strings, duplicate slashes,
a leading HTTP method, a trailing ``:line`` number, and case.

The strategy is a plain function, so you can swap in your own (see
``set_default_strategy`` / the ``signature`` hook documented in the README)
without touching the ledger engine.
"""
from __future__ import annotations

import re
from typing import Callable

from .models import Finding

_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")

SignatureStrategy = Callable[[Finding], str]


def normalize_location(location: str) -> str:
    """Fold incidental differences out of a finding's location string.

    Handles the three common shapes without needing to know which it is:
    a URL/endpoint, a ``path/file.py:42`` source location, or a
    ``package@version`` coordinate.
    """
    loc = (location or "").strip()
    if not loc:
        return ""

    # Drop a leading HTTP method token ("POST /api/x" -> "/api/x").
    head, _, rest = loc.partition(" ")
    if head.lower() in _METHODS and rest:
        loc = rest.strip()

    loc = loc.lower()
    loc = re.sub(r"^[a-z][a-z0-9+.-]*://[^/]+", "", loc)  # strip scheme+host
    loc = loc.split("?", 1)[0].split("#", 1)[0]           # drop query/fragment
    loc = re.sub(r":\d+$", "", loc)                        # drop trailing :line
    loc = re.sub(r"/{2,}", "/", loc)                       # collapse // -> /
    loc = re.sub(r"\s+", " ", loc).strip()
    loc = loc.rstrip("/") or loc or "/"
    return loc


def default_signature(finding: Finding) -> str:
    """The built-in signature strategy."""
    fp = (finding.fingerprint or "").strip()
    if fp:
        return f"fp::{fp}"
    category = (finding.category or "uncategorized").strip().lower()
    return f"{category}::{normalize_location(finding.location)}"


_strategy: SignatureStrategy = default_signature


def signature_of(finding: Finding) -> str:
    """Signature under the currently installed strategy."""
    return _strategy(finding)


def set_default_strategy(strategy: SignatureStrategy) -> None:
    """Install a custom signature strategy process-wide."""
    global _strategy
    _strategy = strategy
