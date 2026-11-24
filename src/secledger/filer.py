"""File ledger entries into a tracker — idempotently.

The filer owns everything the backends don't: severity filtering, the
create-vs-update-vs-skip decision, dry-run, and stamping per-tracker state
back into the ledger so re-runs never double-file.

Idempotency is keyed on two things stamped into ``entry.trackers[name]``:

* ``ref`` — the created issue's id. Present means "already filed"; the filer
  will update (not re-create) from then on.
* ``body_sha256`` — the hash of the last body sent. On an ``--update`` pass,
  an entry whose freshly rendered body hashes the same is skipped, so the
  pass is a no-op when nothing changed.

The ledger is saved after every successful call (via ``on_change``) so a
mid-run failure never re-files what already landed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .ledger import Ledger
from .models import LedgerEntry, SEVERITY_RANK
from .render import body_renderer, content_fingerprint, issue_labels, issue_title
from .trackers.base import Tracker, TrackerError

RenderFn = Callable[[LedgerEntry], str]
LabelsFn = Callable[[LedgerEntry], "list[str]"]


@dataclass
class FileOutcome:
    ledger_id: str
    tracker: str
    action: str  # created | updated | skipped | would-create | would-update | failed
    url: str = ""
    error: str = ""


def file_ledger(
    ledger: Ledger,
    tracker: Tracker,
    *,
    min_severity: str | None = None,
    update: bool = False,
    dry_run: bool = False,
    on_change: Optional[Callable[[], None]] = None,
    title_fn: RenderFn = issue_title,
    body_fn: Optional[RenderFn] = None,
    labels_fn: LabelsFn = issue_labels,
) -> list[FileOutcome]:
    if body_fn is None:
        # Markdown for GitHub/GitLab, wiki markup for Jira.
        body_fn = body_renderer(getattr(tracker, "markup", "markdown"))
    floor = SEVERITY_RANK.get((min_severity or "").lower(), 99)
    outcomes: list[FileOutcome] = []

    for entry in ledger.sorted_by_id():
        if SEVERITY_RANK.get(entry.severity, 0) > floor:
            continue

        title, body, labels = title_fn(entry), body_fn(entry), labels_fn(entry)
        digest = content_fingerprint(title, body, labels)
        state = entry.trackers.get(tracker.name)

        if state is None:
            if dry_run:
                outcomes.append(FileOutcome(entry.ledger_id, tracker.name, "would-create"))
                continue
            try:
                res = tracker.create_issue(title, body, labels)
            except TrackerError as exc:
                outcomes.append(
                    FileOutcome(entry.ledger_id, tracker.name, "failed", error=str(exc))
                )
                continue
            entry.trackers[tracker.name] = {
                "ref": res.get("ref"),
                "url": res.get("url") or "",
                "body_sha256": digest,
            }
            if on_change:
                on_change()
            outcomes.append(
                FileOutcome(entry.ledger_id, tracker.name, "created", url=res.get("url") or "")
            )
            continue

        # Already filed.
        if not update or state.get("body_sha256") == digest:
            outcomes.append(
                FileOutcome(entry.ledger_id, tracker.name, "skipped", url=state.get("url", ""))
            )
            continue
        if dry_run:
            outcomes.append(
                FileOutcome(entry.ledger_id, tracker.name, "would-update", url=state.get("url", ""))
            )
            continue
        try:
            tracker.update_issue(state.get("ref"), title, body, labels)
        except TrackerError as exc:
            outcomes.append(
                FileOutcome(entry.ledger_id, tracker.name, "failed", error=str(exc))
            )
            continue
        state["body_sha256"] = digest
        if on_change:
            on_change()
        outcomes.append(
            FileOutcome(entry.ledger_id, tracker.name, "updated", url=state.get("url", ""))
        )

    return outcomes
