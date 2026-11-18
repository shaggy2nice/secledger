"""Semgrep (``semgrep --json`) -> secledger findings.

Semgrep emits a stable per-result ``extra.fingerprint``, so we pass it through
as the finding ``fingerprint`` — dedup becomes exact rather than heuristic.
"""
from __future__ import annotations

from typing import Any

from .common import (
    SEMGREP_SEVERITY,
    build_document,
    clip,
    dedupe_keep_order,
    default_run_id,
    slug,
)


def _finding(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}
    check_id = str(result.get("check_id", "rule"))
    path = str(result.get("path", ""))
    start = (result.get("start") or {}).get("line", "")
    location = f"{path}:{start}" if path else check_id
    fingerprint = str(extra.get("fingerprint", "")) or ""

    message = str(extra.get("message", "")).strip()
    snippet = str(extra.get("lines", "")).strip()
    description = clip(message)
    if snippet:
        description += f"\n\n```\n{clip(snippet, 1200)}\n```"

    references: list[str] = []
    for cwe in meta.get("cwe", []) if isinstance(meta.get("cwe"), list) else [meta.get("cwe")]:
        if cwe:
            references.append(str(cwe))
    references += [str(r) for r in (meta.get("references") or [])]

    category = slug(
        meta.get("category")
        or (meta.get("owasp")[0] if isinstance(meta.get("owasp"), list) and meta.get("owasp") else "")
        or "sast"
    )

    return {
        "id": fingerprint or f"{check_id}:{path}:{start}",
        "title": message.splitlines()[0] if message else check_id,
        "severity": SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "info"),
        "category": category,
        "location": location,
        "description": description,
        "fingerprint": fingerprint,
        "references": dedupe_keep_order(references),
        "extra": {"check_id": check_id},
    }


def convert(raw: dict[str, Any], *, run_id: str | None = None, target: str = "") -> dict[str, Any]:
    results = raw.get("results") or []
    findings = [_finding(r) for r in results]
    return build_document(
        run_id=run_id or default_run_id(),
        scanner="semgrep",
        target=target,
        findings=findings,
    )
