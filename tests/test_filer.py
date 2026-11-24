from __future__ import annotations

import json

from secledger.filer import file_ledger
from secledger.ledger import Ledger
from secledger.models import Finding, Run

from conftest import FIXTURES, RecordingTracker


def seeded_ledger() -> Ledger:
    ledger = Ledger()
    for name in ("run1.json", "run2.json"):
        doc = json.loads((FIXTURES / name).read_text())
        ledger.merge_run(Run.from_dict(doc["run"]),
                         [Finding.from_dict(f) for f in doc["findings"]])
    return ledger


def test_files_each_entry_once_then_skips():
    ledger = seeded_ledger()
    tr = RecordingTracker()

    first = file_ledger(ledger, tr)
    assert all(o.action == "created" for o in first)
    assert len(tr.created) == len(ledger)
    # every entry now carries the tracker stamp
    assert all("rec" in e.trackers for e in ledger)

    second = file_ledger(ledger, tr)
    assert all(o.action == "skipped" for o in second)
    assert len(tr.created) == len(ledger)  # no new creates


def test_update_only_resends_changed_bodies():
    ledger = seeded_ledger()
    tr = RecordingTracker()
    file_ledger(ledger, tr)

    # No change -> update pass is a no-op.
    out = file_ledger(ledger, tr, update=True)
    assert all(o.action == "skipped" for o in out)
    assert tr.updated == []

    # Change one entry's body; only that one updates.
    target = ledger.sorted_by_id()[0]
    target.title = "Materially different title"
    out = file_ledger(ledger, tr, update=True)
    actions = {o.ledger_id: o.action for o in out}
    assert actions[target.ledger_id] == "updated"
    assert sum(1 for a in actions.values() if a == "updated") == 1
    assert len(tr.updated) == 1


def test_min_severity_filters():
    ledger = seeded_ledger()
    tr = RecordingTracker()
    out = file_ledger(ledger, tr, min_severity="high", dry_run=True)
    # critical SQLi + high XSS qualify; the low info-disclosure does not.
    assert {o.action for o in out} == {"would-create"}
    assert len(out) == 2


def test_dry_run_makes_no_calls():
    ledger = seeded_ledger()
    tr = RecordingTracker()
    out = file_ledger(ledger, tr, dry_run=True)
    assert all(o.action == "would-create" for o in out)
    assert tr.created == []
    assert all("rec" not in e.trackers for e in ledger)


def test_save_called_on_each_success(tmp_path):
    ledger = seeded_ledger()
    tr = RecordingTracker()
    saves = []
    file_ledger(ledger, tr, on_change=lambda: saves.append(1))
    assert len(saves) == len(ledger)


def test_body_markup_follows_the_tracker():
    ledger = seeded_ledger()
    markdown, wiki = RecordingTracker(), RecordingTracker()
    wiki.name, wiki.markup = "rec-jira", "jira"

    file_ledger(ledger, markdown)
    file_ledger(ledger, wiki)  # same ledger, second tracker: no collision

    assert "| --- |" in markdown.created[0][1]
    assert "h3. Finding" in wiki.created[0][1]
    assert all({"rec", "rec-jira"} <= set(e.trackers) for e in ledger)
