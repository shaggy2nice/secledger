from __future__ import annotations

from secledger.models import Alias, LedgerEntry
from secledger.render import (
    body_fingerprint,
    content_fingerprint,
    issue_body,
    issue_labels,
    issue_title,
)


def mk_entry() -> LedgerEntry:
    return LedgerEntry(
        ledger_id="SL-0001",
        signature="xss::/search",
        title="Reflected XSS in search",
        category="xss",
        severity="high",
        status="confirmed",
        first_seen="r1",
        last_seen="r2",
        times_seen=2,
        aliases=[
            Alias(run="r1", id="f1", title="XSS", location="/search", severity="high", status="confirmed"),
            Alias(run="r2", id="a", title="XSS again", location="/search", severity="medium"),
        ],
    )


def test_title_includes_id_and_severity():
    assert issue_title(mk_entry()).startswith("[SL-0001] (high)")


def test_labels_are_scoped():
    labels = issue_labels(mk_entry())
    assert "secledger" in labels
    assert "sev:high" in labels
    assert "cat:xss" in labels
    assert "sl-0001" in labels


def test_body_contains_key_fields_and_is_markdown():
    body = issue_body(mk_entry())
    assert "SL-0001" in body
    assert "`xss::/search`" in body
    assert "**Locations**" in body
    assert "/search" in body


def test_body_fingerprint_is_stable_and_changes_with_body_content():
    e = mk_entry()
    h1 = body_fingerprint(issue_body(e))
    assert body_fingerprint(issue_body(e)) == h1
    e.severity = "low"  # severity is rendered into the body table
    assert body_fingerprint(issue_body(e)) != h1


def test_content_fingerprint_reflects_title_and_labels():
    e = mk_entry()
    base = content_fingerprint(issue_title(e), issue_body(e), issue_labels(e))
    # A title-only change (title isn't in the body) must still change the hash.
    e.title = "Materially different title"
    assert content_fingerprint(issue_title(e), issue_body(e), issue_labels(e)) != base
