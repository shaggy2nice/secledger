# Writing a secledger adapter

An **adapter** turns one scanner's native JSON into the secledger findings
schema. That's the only integration point — once your scanner's output is in
the schema, `ingest`, dedup, and filing all work unchanged.

The three shipped adapters (`semgrep.py`, `trivy.py`, `zap.py`) are working
examples; most adapters are 30–40 lines. This guide walks through writing your
own and contributing it back so others can use your scanner too.

## The contract

An adapter is one function:

```python
def convert(raw: dict, *, run_id: str | None = None, target: str = "") -> dict:
    ...
```

- `raw` — the scanner's parsed JSON (a `dict`).
- `run_id` — the id to stamp on this run; default to a timestamp when `None`.
- `target` — optional label for what was scanned.
- **returns** a findings document: `{"schema_version", "run", "findings"}`.

Use the helper so you don't hand-build the envelope:

```python
from .common import build_document, default_run_id

return build_document(
    run_id=run_id or default_run_id(),
    scanner="myscanner",
    target=target,
    findings=[...],
)
```

## The finding shape

Each item in `findings` is a dict. Only `id` is required:

| field | required | notes |
| --- | --- | --- |
| `id` | ✅ | unique **within the run** (a native id, or `rule:path:line`) |
| `title` | — | short, human-readable |
| `severity` | — | `critical` / `high` / `medium` / `low` / `info` (default `info`) |
| `category` | — | taxonomy string; part of the default signature |
| `location` | — | `endpoint`, `path/file.py:line`, or `pkg@version` |
| `description` | — | Markdown; becomes the issue body |
| `status` | — | `confirmed`/`verified` promote the ledger entry |
| `references` | — | list of strings (CWE, CVE, URLs) |
| `fingerprint` | — | **the dedup lever — see below** |
| `extra` | — | passthrough dict for anything scanner-specific |

## The one real decision: `fingerprint` vs `category::location`

This is what makes a good adapter. secledger's signature (the dedup key) is:

- `fp::<fingerprint>` when you set `fingerprint` — **exact** dedup.
- `category :: normalized(location)` otherwise — **heuristic** dedup that folds
  away scheme/host/query/method/line-number/case.

Choose per scanner:

- **Set `fingerprint`** when the scanner emits a stable id for the same issue
  across runs (Semgrep's `extra.fingerprint`, a `CVE:package` pair for a
  dependency scanner). This is the most reliable dedup.
- **Leave it empty** when you *want* location-based merging — e.g. a DAST alert
  type that should produce one ledger entry per endpoint. Make `category` a
  stable slug of the alert type (`slug("Reflected XSS")` → `reflected_xss`) so
  the signature is `reflected_xss::/the/path`.

Getting this right is the difference between a clean ledger and either
duplicate issues or over-merged ones.

## A complete minimal example

A hypothetical `mytool` that emits `{"issues": [...]}`:

```python
# src/secledger/adapters/mytool.py
from __future__ import annotations
from typing import Any
from .common import build_document, clip, default_run_id, slug

_SEV = {"BLOCKER": "critical", "MAJOR": "high", "MINOR": "medium", "INFO": "info"}

def _finding(issue: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(issue["key"]),
        "title": str(issue.get("message", "")),
        "severity": _SEV.get(str(issue.get("severity", "")).upper(), "info"),
        "category": slug(issue.get("rule", "")),
        "location": f"{issue.get('file','')}:{issue.get('line','')}",
        "description": clip(str(issue.get("message", ""))),
        "fingerprint": str(issue.get("hash", "")),  # exact dedup if present
        "references": [str(r) for r in issue.get("cwe", [])],
    }

def convert(raw, *, run_id=None, target=""):
    findings = [_finding(i) for i in raw.get("issues", [])]
    return build_document(run_id=run_id or default_run_id(),
                          scanner="mytool", target=target, findings=findings)
```

## Register it

Add it to the registry in [`__init__.py`](__init__.py):

```python
from . import mytool
ADAPTERS = {..., "mytool": mytool.convert}
```

That's all the CLI needs — `secledger-adapt mytool ...` now works, stdin/stdout
and all. (No `cli.py` change required; the CLI reads the registry.)

## Test it

1. Drop a **synthetic** sample of the scanner's output in
   `examples/adapters/mytool.raw.json`. Never commit real findings, hostnames,
   or tokens.
2. Add a test in `tests/test_adapters.py` that converts it, calls
   `validate_document(doc)`, and asserts the severity/location/fingerprint
   mapping you care about.

```bash
pytest tests/test_adapters.py -q
```

## Conventions worth keeping

- Be defensive: scanners omit fields. Use `.get(..., default)` everywhere.
- Keep severity maps near the top and documented — they're the first thing a
  team tunes.
- Truncate long descriptions with `common.clip` so issue bodies stay readable.
- Deterministic output: given the same input + `run_id`, produce byte-identical
  results (the idempotency guarantees depend on it — don't inject timestamps
  into finding bodies).
- Open a PR! A new adapter helps everyone running that scanner. See
  [`../../../CONTRIBUTING.md`](../../../CONTRIBUTING.md).
