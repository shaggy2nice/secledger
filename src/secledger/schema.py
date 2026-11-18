"""Light validation for the input findings file.

Deliberately hand-rolled (no ``jsonschema`` dependency) so the tool stays
pure-stdlib. It checks the shape secledger relies on and raises a clear
``SchemaError`` otherwise; it does not try to be a full JSON-Schema engine.

Input contract (one scanner run)::

    {
      "schema_version": "1.0",
      "run": {"id": "<run id>", "scanner": "<name>", "target": "<name>"},
      "findings": [
        {
          "id": "<scanner-local id>",       # required
          "title": "<short title>",
          "severity": "critical|high|medium|low|info",
          "category": "<taxonomy string>",
          "location": "<endpoint | file:line | pkg@ver>",
          "description": "<markdown body>",
          "status": "<e.g. confirmed>",     # optional
          "references": ["CWE-918", "..."], # optional
          "fingerprint": "<stable id>",     # optional; exact dedup when set
          "extra": { ... }                  # optional passthrough
        }
      ]
    }
"""
from __future__ import annotations

from typing import Any

SCHEMA_VERSION = "1.0"


class SchemaError(ValueError):
    """Raised when an input findings document doesn't match the contract."""


def validate_document(doc: Any) -> None:
    if not isinstance(doc, dict):
        raise SchemaError("top level must be a JSON object")

    run = doc.get("run")
    if not isinstance(run, dict):
        raise SchemaError("'run' must be an object")
    if not str(run.get("id", "")).strip():
        raise SchemaError("'run.id' is required and must be non-empty")

    findings = doc.get("findings")
    if not isinstance(findings, list):
        raise SchemaError("'findings' must be a list")

    seen_ids: set[str] = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise SchemaError(f"{where} must be an object")
        fid = str(f.get("id", "")).strip()
        if not fid:
            raise SchemaError(f"{where}.id is required and must be non-empty")
        if fid in seen_ids:
            raise SchemaError(f"{where}.id '{fid}' is duplicated within the run")
        seen_ids.add(fid)
        sev = f.get("severity")
        if sev is not None and not isinstance(sev, str):
            raise SchemaError(f"{where}.severity must be a string")
        refs = f.get("references")
        if refs is not None and not isinstance(refs, list):
            raise SchemaError(f"{where}.references must be a list")
        extra = f.get("extra")
        if extra is not None and not isinstance(extra, dict):
            raise SchemaError(f"{where}.extra must be an object")
