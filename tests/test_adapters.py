from __future__ import annotations

import json

from secledger.adapters import available, get_adapter
from secledger.adapters.cli import main as adapt_main
from secledger.ledger import Ledger
from secledger.models import Finding, Run
from secledger.schema import validate_document

from conftest import EXAMPLES


def _convert(scanner, **kw):
    raw = json.loads((EXAMPLES / "adapters" / f"{scanner}.raw.json").read_text())
    return get_adapter(scanner)(raw, run_id="r1", target="dev", **kw)


def test_registry_lists_all_three():
    assert set(available()) == {"semgrep", "trivy", "zap"}


def test_all_adapters_emit_valid_documents():
    for scanner in available():
        doc = _convert(scanner)
        validate_document(doc)  # raises on failure
        assert doc["run"]["id"] == "r1"
        assert doc["findings"]


def test_semgrep_mapping():
    doc = _convert("semgrep")
    assert len(doc["findings"]) == 2
    sqli = doc["findings"][0]
    assert sqli["severity"] == "high"               # ERROR -> high
    assert sqli["location"] == "app/db.py:42"
    assert sqli["fingerprint"] == "abc123def456"    # passthrough
    assert sqli["id"] == "abc123def456"
    assert doc["findings"][1]["severity"] == "medium"  # WARNING -> medium


def test_trivy_mapping():
    doc = _convert("trivy")
    assert len(doc["findings"]) == 2
    byloc = {f["location"]: f for f in doc["findings"]}
    assert byloc["libexample@1.2.3"]["severity"] == "high"
    assert byloc["libexample@1.2.3"]["fingerprint"] == "CVE-2025-11111:libexample"
    assert byloc["libexample@1.2.3"]["status"] == "confirmed"
    assert byloc["demo-lib@4.0.0"]["severity"] == "critical"


def test_zap_mapping_and_no_fingerprint():
    doc = _convert("zap")
    assert len(doc["findings"]) == 2
    xss = next(f for f in doc["findings"] if "Scripting" in f["title"])
    assert xss["severity"] == "high"                 # riskcode 3
    assert xss["category"] == "cross_site_scripting_reflected"
    assert xss["location"] == "GET https://dev.example.app/search?q=1"
    assert not xss.get("fingerprint")                # relies on category::location
    assert "CWE-79" in xss["references"]


def test_adapter_output_ingests_and_dedupes():
    # ZAP XSS at /search normalizes to the same signature as a hand-written run.
    doc = _convert("zap")
    ledger = Ledger()
    ledger.merge_run(Run.from_dict(doc["run"]),
                     [Finding.from_dict(f) for f in doc["findings"]])
    sigs = {e.signature for e in ledger}
    assert "cross_site_scripting_reflected::/search" in sigs
    assert len(ledger) == 2


def test_cli_stdin_to_stdout(capsys, monkeypatch):
    raw = (EXAMPLES / "adapters" / "trivy.raw.json").read_text()
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))
    rc = adapt_main(["trivy", "--run-id", "r1", "--target", "dev"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    validate_document(doc)
    assert len(doc["findings"]) == 2
