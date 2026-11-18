from __future__ import annotations

import json

from secledger.cli import main

from conftest import FIXTURES


def test_ingest_creates_ledger_and_markdown(tmp_path, capsys):
    ledger = tmp_path / "ledger.json"
    rc = main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)])
    assert rc == 0
    assert ledger.exists()
    assert (tmp_path / "LEDGER.md").exists()
    data = json.loads(ledger.read_text())
    assert len(data) == 2
    out = capsys.readouterr().out
    assert "NEW SL-0001" in out


def test_ingest_twice_is_idempotent(tmp_path):
    ledger = tmp_path / "ledger.json"
    main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)])
    main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)])
    assert len(json.loads(ledger.read_text())) == 2


def test_ingest_two_runs_merges(tmp_path):
    ledger = tmp_path / "ledger.json"
    main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)])
    main(["ingest", str(FIXTURES / "run2.json"), "--ledger", str(ledger)])
    assert len(json.loads(ledger.read_text())) == 3


def test_file_dry_run_needs_no_token(tmp_path, capsys):
    ledger = tmp_path / "ledger.json"
    main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)])
    rc = main([
        "file", "--ledger", str(ledger), "--tracker", "gitlab",
        "--url", "https://gl.test", "--project", "g/p", "--dry-run",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "WOULD-CREATE" in out


def test_show_json(tmp_path, capsys):
    ledger = tmp_path / "ledger.json"
    main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)])
    capsys.readouterr()  # flush ingest output so we only parse `show`'s JSON
    rc = main(["show", "--ledger", str(ledger), "--format", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)


def test_invalid_document_reports_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"run": {}, "findings": []}))
    rc = main(["ingest", str(bad), "--ledger", str(tmp_path / "l.json")])
    assert rc == 1
    assert "invalid findings document" in capsys.readouterr().err
