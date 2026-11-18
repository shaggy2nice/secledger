"""The cross-run ledger: load, merge one run, save.

Merge rules (all deterministic, so re-ingesting the same run is a no-op):

* A finding whose signature is new becomes a new ``LedgerEntry`` with the next
  ``SL-NNNN`` id.
* A finding whose signature already exists is recorded as an ``Alias`` on the
  existing entry — unless that exact ``(run, id)`` alias is already present, in
  which case nothing changes (idempotency).
* ``first_seen`` / ``last_seen`` / ``times_seen`` track the span and count of
  distinct aliases.
* The entry's headline ``severity`` is the **highest** severity any alias ever
  carried; its ``title`` follows the most recent confirmed alias (most recent
  overall if none is confirmed), so the ledger reads as the best current
  description of the issue.

The signature is a *deterministic text key*, not a semantic judge: it can
merge two genuinely different bugs that share a category+location, or split
one bug described at two locations. Treat a ``NEW`` line as "look at this",
and skim merges before trusting them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import (
    Alias,
    Finding,
    LedgerEntry,
    Run,
    SEVERITY_RANK,
    normalize_severity,
)
from .signature import signature_of

LEDGER_ID_PREFIX = "SL"
LEDGER_ID_WIDTH = 4


@dataclass
class MergeResult:
    new_entries: list[LedgerEntry]
    updated_entries: list[LedgerEntry]

    @property
    def is_noop(self) -> bool:
        return not self.new_entries and not self.updated_entries


class Ledger:
    """An ordered collection of :class:`LedgerEntry`, keyed by signature."""

    def __init__(self, entries: Iterable[LedgerEntry] | None = None) -> None:
        self._entries: list[LedgerEntry] = list(entries or [])
        self._by_sig: dict[str, LedgerEntry] = {
            e.signature: e for e in self._entries
        }

    # ---- persistence -----------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "Ledger":
        p = Path(path)
        if not p.exists():
            return cls([])
        data = json.loads(p.read_text() or "[]")
        return cls([LedgerEntry.from_dict(d) for d in data])

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = [e.to_dict() for e in self.sorted_by_id()]
        p.write_text(json.dumps(payload, indent=2) + "\n")

    # ---- access ----------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    @property
    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def sorted_by_id(self) -> list[LedgerEntry]:
        return sorted(self._entries, key=lambda e: e.ledger_id)

    def sorted_by_severity(self) -> list[LedgerEntry]:
        return sorted(
            self._entries,
            key=lambda e: (SEVERITY_RANK.get(e.severity, 99), e.ledger_id),
        )

    # ---- merge -----------------------------------------------------------

    def _next_id(self) -> str:
        nums = [
            int(e.ledger_id.split("-", 1)[1])
            for e in self._entries
            if e.ledger_id.startswith(LEDGER_ID_PREFIX + "-")
            and e.ledger_id.split("-", 1)[1].isdigit()
        ]
        n = (max(nums) + 1) if nums else 1
        return f"{LEDGER_ID_PREFIX}-{n:0{LEDGER_ID_WIDTH}d}"

    def merge_run(self, run: Run, findings: Iterable[Finding]) -> MergeResult:
        new: list[LedgerEntry] = []
        updated: list[LedgerEntry] = []

        for finding in findings:
            sig = signature_of(finding)
            alias = Alias(
                run=run.id,
                id=finding.id,
                title=finding.title,
                location=finding.location,
                severity=finding.severity,
                status=finding.status,
            )
            entry = self._by_sig.get(sig)
            if entry is None:
                entry = LedgerEntry(
                    ledger_id=self._next_id(),
                    signature=sig,
                    title=finding.title,
                    category=finding.category,
                    severity=finding.severity,
                    status=finding.status,
                    first_seen=run.id,
                    last_seen=run.id,
                    times_seen=1,
                    aliases=[alias],
                )
                self._entries.append(entry)
                self._by_sig[sig] = entry
                new.append(entry)
                continue

            # Existing signature: idempotent on (run, id).
            if any(a.run == alias.run and a.id == alias.id for a in entry.aliases):
                continue
            entry.aliases.append(alias)
            self._recompute(entry)
            updated.append(entry)

        return MergeResult(new_entries=new, updated_entries=updated)

    @staticmethod
    def _recompute(entry: LedgerEntry) -> None:
        aliases = entry.aliases
        entry.times_seen = len(aliases)
        runs = [a.run for a in aliases if a.run]
        if runs:
            entry.first_seen = min(runs)
            entry.last_seen = max(runs)
        # Highest severity any alias ever carried.
        entry.severity = min(
            (a.severity for a in aliases),
            key=lambda s: SEVERITY_RANK.get(normalize_severity(s), 99),
            default=entry.severity,
        )
        # Title/status follow the newest confirmed alias, else newest overall.
        from .models import CONFIRMED_STATUSES

        ordered = sorted(aliases, key=lambda a: a.run, reverse=True)
        best = next(
            (a for a in ordered if a.status.strip().lower() in CONFIRMED_STATUSES),
            ordered[0] if ordered else None,
        )
        if best is not None:
            entry.title = best.title or entry.title
            entry.status = best.status or entry.status


def render_ledger_markdown(ledger: Ledger, run_count: int | None = None) -> str:
    """A human-readable LEDGER.md view, sorted by severity."""
    n_runs = run_count if run_count is not None else "?"
    lines = [
        "# Findings ledger",
        "",
        f"{len(ledger)} distinct findings"
        + (f" across {n_runs} runs" if run_count is not None else "")
        + ". Deterministic signature dedup; verify before trusting a merge.",
        "",
    ]
    for e in ledger.sorted_by_severity():
        lines += [
            f"## {e.ledger_id} — {e.title}",
            f"- category: {e.category}  severity: {e.severity}  "
            f"status: {e.status or 'unverified'}",
            f"- signature: `{e.signature}`",
            f"- seen {e.times_seen}x, first {e.first_seen}, last {e.last_seen}",
            "",
        ]
    return "\n".join(lines)
