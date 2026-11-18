"""Data model for findings, ledger entries, and the input run envelope.

Two layers:

* **Finding** / **Run** — what a scanner emits. A thin, tool-agnostic shape
  (see ``schema.py`` for the on-disk JSON contract). One Finding is one raw
  observation from one run.
* **LedgerEntry** — what secledger maintains. One distinct issue, collapsed
  across every run that reported it, with per-run ``aliases`` and per-tracker
  filing state.

Everything is a plain dataclass with ``to_dict`` / ``from_dict`` so the
ledger is human-readable JSON you can diff in code review.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Statuses are free-form, but these are recognized for the "confirmed beats
# unconfirmed" promotion rule in the ledger merge. Anything else is treated
# as unconfirmed.
CONFIRMED_STATUSES = frozenset({"confirmed", "verified", "true_positive"})


def normalize_severity(value: str | None) -> str:
    v = (value or "").strip().lower()
    return v if v in SEVERITY_RANK else "info"


@dataclass
class Run:
    """The envelope around one scanner run's findings."""

    id: str
    scanner: str = ""
    target: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Run":
        return cls(
            id=str(d["id"]),
            scanner=str(d.get("scanner", "")),
            target=str(d.get("target", "")),
        )


@dataclass
class Finding:
    """One raw finding from one run."""

    id: str
    title: str
    severity: str = "info"
    category: str = "uncategorized"
    location: str = ""
    description: str = ""
    status: str = ""
    references: list[str] = field(default_factory=list)
    # A stable, scanner-supplied identifier (e.g. a Semgrep/CodeQL
    # fingerprint). When present it takes precedence over the computed
    # signature, which makes dedup exact instead of heuristic.
    fingerprint: str = ""
    # Anything else the scanner wants to carry through to the issue body.
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            id=str(d["id"]),
            title=str(d.get("title") or d["id"]),
            severity=normalize_severity(d.get("severity")),
            category=str(d.get("category") or "uncategorized").strip().lower(),
            location=str(d.get("location", "")),
            description=str(d.get("description", "")),
            status=str(d.get("status", "")),
            references=[str(r) for r in (d.get("references") or [])],
            fingerprint=str(d.get("fingerprint", "")),
            extra=dict(d.get("extra") or {}),
        )

    def is_confirmed(self) -> bool:
        return self.status.strip().lower() in CONFIRMED_STATUSES


@dataclass
class Alias:
    """A per-run record of one finding behind a ledger entry."""

    run: str
    id: str
    title: str = ""
    location: str = ""
    severity: str = "info"
    status: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alias":
        return cls(
            run=str(d.get("run", "")),
            id=str(d.get("id", "")),
            title=str(d.get("title", "")),
            location=str(d.get("location", "")),
            severity=normalize_severity(d.get("severity")),
            status=str(d.get("status", "")),
        )


@dataclass
class LedgerEntry:
    """One distinct finding, collapsed across every run that reported it."""

    ledger_id: str
    signature: str
    title: str
    category: str = "uncategorized"
    severity: str = "info"
    status: str = ""
    first_seen: str = ""
    last_seen: str = ""
    times_seen: int = 0
    aliases: list[Alias] = field(default_factory=list)
    # Per-tracker filing state, keyed by tracker name, e.g.
    #   {"gitlab": {"ref": 42, "url": "...", "body_sha256": "..."}}
    # Keeping this a dict (not flat fields) lets one ledger be filed into
    # several trackers at once without them colliding.
    trackers: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LedgerEntry":
        return cls(
            ledger_id=str(d["ledger_id"]),
            signature=str(d["signature"]),
            title=str(d.get("title", "")),
            category=str(d.get("category", "uncategorized")),
            severity=normalize_severity(d.get("severity")),
            status=str(d.get("status", "")),
            first_seen=str(d.get("first_seen", "")),
            last_seen=str(d.get("last_seen", "")),
            times_seen=int(d.get("times_seen", 0)),
            aliases=[Alias.from_dict(a) for a in (d.get("aliases") or [])],
            trackers=dict(d.get("trackers") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger_id": self.ledger_id,
            "signature": self.signature,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "times_seen": self.times_seen,
            "aliases": [asdict(a) for a in self.aliases],
            "trackers": self.trackers,
        }
