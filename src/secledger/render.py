"""Render a ledger entry to a tracker-neutral Markdown issue body.

GitHub and GitLab both accept GitHub-Flavored Markdown natively, so one
renderer serves both. The body is deterministic: the same entry always
produces byte-identical output, which is what makes the "skip unchanged on
re-file" check reliable (see ``trackers.base``).
"""
from __future__ import annotations

import hashlib

from .models import LedgerEntry


def issue_title(entry: LedgerEntry) -> str:
    return f"[{entry.ledger_id}] ({entry.severity}) {entry.title}"[:255]


def issue_labels(entry: LedgerEntry) -> list[str]:
    return [
        "secledger",
        f"sev:{entry.severity}",
        f"cat:{entry.category}",
        entry.ledger_id.lower(),
    ]


def issue_body(entry: LedgerEntry) -> str:
    lines: list[str] = []
    lines.append(f"_Filed by secledger from ledger entry {entry.ledger_id}._")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.append(f"| ledger id | `{entry.ledger_id}` |")
    lines.append(f"| category | {entry.category} |")
    lines.append(f"| severity | {entry.severity} |")
    lines.append(f"| status | {entry.status or 'unverified'} |")
    lines.append(f"| signature | `{entry.signature}` |")
    lines.append(
        f"| seen | {entry.times_seen}x — first {entry.first_seen}, "
        f"last {entry.last_seen} |"
    )
    lines.append("")

    locations = sorted({a.location for a in entry.aliases if a.location})
    if locations:
        lines.append("**Locations**")
        for loc in locations:
            lines.append(f"- `{loc}`")
        lines.append("")

    lines.append("**Observed in**")
    for a in entry.aliases:
        status = f", {a.status}" if a.status else ""
        lines.append(
            f"- {a.run} / {a.id} [{a.severity}{status}] {a.title}".rstrip()
        )
    lines.append("")
    lines.append(
        "_Dedup is a deterministic signature, so confirm the merge before "
        "closing this as one issue._"
    )
    return "\n".join(lines)


def body_fingerprint(body: str) -> str:
    """Stable hash of an issue body string."""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def content_fingerprint(title: str, body: str, labels: list[str]) -> str:
    """Stable hash of everything we would send for an issue — title, body, and
    labels — stamped into the ledger so an unchanged issue skips the update
    call on the next ``file`` pass. Covering the title (not just the body)
    means a title-only change still triggers an update."""
    h = hashlib.sha256()
    for part in (title, body, ",".join(labels)):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()
