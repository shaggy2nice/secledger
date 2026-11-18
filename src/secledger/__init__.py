"""secledger — a deterministic, idempotent security-findings ledger.

Ingest findings from any scanner (via a small common JSON schema), dedupe
them across runs into a stable ledger, and file one issue per distinct
finding into an issue tracker (GitLab, GitHub, ...) without ever
double-filing.

Pure standard library — no runtime dependencies — so it drops cleanly into
air-gapped and restricted environments.
"""
from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
