"""Tracker backend interface + a dependency-free HTTP transport.

A :class:`Tracker` knows how to create and update one issue in one tracker.
It does *not* know about the ledger, idempotency, or dry-run — that
orchestration lives in :mod:`secledger.filer`, so every backend stays tiny.

HTTP goes through an injectable ``transport`` callable so the backends are
unit-testable without a network: tests pass a fake transport that records the
request and returns a canned response. The default transport is a thin
``urllib`` wrapper (no third-party HTTP dependency), with optional CA-bundle
support for self-hosted instances presenting a private/enterprise CA.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional, Tuple

# transport(method, url, headers, body_bytes) -> (status_code, response_bytes)
Transport = Callable[[str, str, dict, Optional[bytes]], Tuple[int, bytes]]


class TrackerError(RuntimeError):
    """A tracker API call failed (HTTP error, transport error, bad response)."""


def urllib_transport(ca_bundle: str | None = None, timeout: float = 60.0) -> Transport:
    """Default transport: ``urllib`` with an optional CA bundle."""
    context = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else None

    def _transport(method, url, headers, body):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                return resp.getcode(), resp.read()
        except urllib.error.HTTPError as exc:  # 4xx/5xx carry a body
            return exc.code, exc.read()

    return _transport


class Tracker(ABC):
    """Base class for issue-tracker backends.

    Subclasses implement :meth:`create_issue` and :meth:`update_issue` and may
    use the :meth:`request` helper. ``name`` is the stable key the ledger uses
    to stamp per-tracker filing state, so it must not change across versions.
    """

    name: str = "tracker"

    def __init__(
        self,
        *,
        base_url: str,
        project: str,
        token: str,
        token_type: str = "token",
        ca_bundle: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        if not base_url:
            raise TrackerError(f"{self.name}: base_url is required")
        if not project:
            raise TrackerError(f"{self.name}: project/repo is required")
        self.base_url = base_url.rstrip("/")
        self.project = project
        self.token = token
        self.token_type = token_type
        self._transport = transport or urllib_transport(ca_bundle)

    # ---- helpers ---------------------------------------------------------

    @abstractmethod
    def auth_headers(self) -> dict:
        """Authorization header(s) for this tracker."""

    def request(self, method: str, url: str, payload: dict | None = None) -> dict:
        headers = {"Accept": "application/json", **self.auth_headers()}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, raw = self._transport(method, url, headers, body)
        if status >= 400:
            snippet = raw.decode("utf-8", "replace")[:500]
            raise TrackerError(f"{self.name}: HTTP {status} for {method} {url}: {snippet}")
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TrackerError(f"{self.name}: non-JSON response: {exc}") from exc

    # ---- backend contract ------------------------------------------------

    @abstractmethod
    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        """Create an issue. Return ``{"ref": <id>, "url": <str>}``."""

    @abstractmethod
    def update_issue(self, ref: Any, title: str, body: str, labels: list[str]) -> None:
        """Update an existing issue's body/labels."""
