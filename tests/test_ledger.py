from __future__ import annotations

import json

from secledger.ledger import Ledger
from secledger.models import Finding, Run

from conftest import FIXTURES


def load_run(name):
    doc = json.loads((FIXTURES / name).read_text())
    return Run.from_dict(doc["run"]), [Finding.from_dict(f) for f in doc["findings"]]


def test_first_run_creates_entries():
    run, findings = load_run("run1.json")
    ledger = Ledger()
    result = ledger.merge_run(run, findings)
    assert len(result.new_entries) == 2
    assert len(ledger) == 2
    assert [e.ledger_id for e in ledger.sorted_by_id()] == ["SL-0001", "SL-0002"]


def test_reingest_same_run_is_noop():
    run, findings = load_run("run1.json")
    ledger = Ledger()
    ledger.merge_run(run, findings)
    result = ledger.merge_run(run, findings)
    assert result.is_noop
    assert len(ledger) == 2


def test_second_run_merges_and_adds():
    ledger = Ledger()
    ledger.merge_run(*load_run("run1.json"))
    result = ledger.merge_run(*load_run("run2.json"))

    # run2 "a" merges into the XSS entry; "b" is a brand-new SQLi finding.
    assert len(result.new_entries) == 1
    assert len(result.updated_entries) == 1
    assert len(ledger) == 3

    xss = next(e for e in ledger if e.signature == "xss::/search")
    assert xss.times_seen == 2
    assert xss.first_seen == "2026-01-01T00-00-00Z"
    assert xss.last_seen == "2026-02-01T00-00-00Z"
    # headline severity is the worst ever seen (high beats the later medium)
    assert xss.severity == "high"


def test_fingerprint_entry_present():
    ledger = Ledger()
    ledger.merge_run(*load_run("run2.json"))
    assert any(e.signature == "fp::demo-sqli-0001" for e in ledger)


def test_save_and_load_roundtrip(tmp_path):
    ledger = Ledger()
    ledger.merge_run(*load_run("run1.json"))
    ledger.merge_run(*load_run("run2.json"))
    p = tmp_path / "ledger.json"
    ledger.save(p)

    reloaded = Ledger.load(p)
    assert len(reloaded) == len(ledger)
    assert {e.signature for e in reloaded} == {e.signature for e in ledger}


def test_severity_escalates_not_downgrades():
    ledger = Ledger()
    run = Run(id="r1")
    ledger.merge_run(run, [Finding.from_dict(
        {"id": "x", "title": "t", "severity": "low", "category": "c", "location": "/p"})])
    ledger.merge_run(Run(id="r2"), [Finding.from_dict(
        {"id": "x", "title": "t", "severity": "critical", "category": "c", "location": "/p"})])
    entry = ledger.entries[0]
    assert entry.severity == "critical"
    assert entry.times_seen == 2
