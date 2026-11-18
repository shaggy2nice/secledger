"""Shared helpers for the example scanner adapters.

An adapter is a small, dependency-free function that maps one scanner's native
JSON into the secledger findings schema (see ``secledger.schema``). These three
(Semgrep, Trivy, OWASP ZAP) are meant as working, copyable examples — fork one
for your scanner of choice; the mapping is usually 30-40 lines.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Native severity -> secledger severity. Tune to taste; these are conventions,
# not law, and are exactly the kind of thing a team adjusts for its own triage.
SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
    "INVENTORY": "info",
    "EXPERIMENT": "info",
}
TRIVY_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}
ZAP_RISK = {3: "high", 2: "medium", 1: "low", 0: "info"}


def default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def slug(text: str) -> str:
    """A stable, lowercase slug for use in a category/signature."""
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").strip().lower())
    return s.strip("_") or "uncategorized"


def dedupe_keep_order(items: list[str], limit: int = 12) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        it = str(it).strip()
        if it and it not in seen:
            seen.add(it)
            out.append(it)
        if len(out) >= limit:
            break
    return out


def build_document(
    *, run_id: str, scanner: str, target: str, findings: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "run": {"id": run_id, "scanner": scanner, "target": target},
        "findings": findings,
    }


def clip(text: str, limit: int = 4000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit].rstrip() + " …"
