"""Render a ledger entry to an issue title, labels, and body.

GitHub and GitLab both accept GitHub-Flavored Markdown natively, so one
Markdown renderer serves both. Jira takes its own wiki markup, so it gets a
second renderer with the same content; :func:`body_renderer` picks one from a
tracker's ``markup``. Every body is deterministic: the same entry always
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


def _noformat(lines: list[str]) -> list[str]:
    """Wrap lines in a Jira ``{noformat}`` block so they show exactly as written.

    Finding text is free-form, and Jira wiki markup reads ``{...}``, ``[...]``
    and ``|`` as syntax: a location such as ``GET /api/{id}`` would render as
    an "unknown macro" error. So everything that came from a scanner goes
    inside a block instead of being escaped character by character.
    """
    safe = [ln.replace("{noformat}", "{ noformat }") for ln in lines]
    return ["{noformat}", *safe, "{noformat}"]


def issue_body_jira(entry: LedgerEntry) -> str:
    """The same content as :func:`issue_body`, in Jira wiki markup."""
    lines: list[str] = []
    lines.append(f"_Filed by secledger from ledger entry {entry.ledger_id}._")
    lines.append("")
    lines.append("h3. Finding")
    lines += _noformat([
        f"ledger id:  {entry.ledger_id}",
        f"category:   {entry.category}",
        f"severity:   {entry.severity}",
        f"status:     {entry.status or 'unverified'}",
        f"signature:  {entry.signature}",
        f"seen:       {entry.times_seen}x, first {entry.first_seen}, "
        f"last {entry.last_seen}",
    ])
    lines.append("")

    locations = sorted({a.location for a in entry.aliases if a.location})
    if locations:
        lines.append("h3. Locations")
        lines += _noformat(locations)
        lines.append("")

    lines.append("h3. Observed in")
    observed = []
    for a in entry.aliases:
        status = f", {a.status}" if a.status else ""
        observed.append(
            f"{a.run} / {a.id} [{a.severity}{status}] {a.title}".rstrip()
        )
    lines += _noformat(observed)
    lines.append("")
    lines.append(
        "_Dedup is a deterministic signature, so confirm the merge before "
        "closing this as one issue._"
    )
    return "\n".join(lines)


BODY_RENDERERS = {"markdown": issue_body, "jira": issue_body_jira}


def body_renderer(markup: str):
    """The body renderer for a tracker's markup dialect (``Tracker.markup``)."""
    try:
        return BODY_RENDERERS[markup]
    except KeyError:
        raise ValueError(
            f"no body renderer for markup {markup!r}; "
            f"available: {', '.join(sorted(BODY_RENDERERS))}"
        )


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
