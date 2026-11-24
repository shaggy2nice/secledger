"""End-to-end: the Jira backend over the real ``urllib`` transport.

The unit tests in ``test_jira.py`` drive the backend through a fake
transport. These run it, and the CLI, against ``mock_jira.MockJira`` on a
loopback port, so real HTTP, real headers and real status handling are
exercised. Nothing leaves the machine.
"""
from __future__ import annotations

import json

import pytest

from secledger.cli import main
from secledger.trackers import JiraError, JiraTracker

from conftest import FIXTURES
from mock_jira import MockJira


@pytest.fixture
def jira(monkeypatch):
    # A proxy configured in the environment must not swallow loopback calls.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    for name in ("JIRA_URL", "JIRA_PROJECT", "JIRA_TOKEN", "JIRA_EMAIL",
                 "JIRA_TOKEN_TYPE", "JIRA_ISSUE_TYPE", "JIRA_SET_PRIORITY",
                 "SECLEDGER_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    with MockJira() as mock:
        yield mock


def tracker_for(mock: MockJira, **kwargs) -> tuple[JiraTracker, list[float]]:
    sleeps: list[float] = []
    kwargs.setdefault("email", mock.email)
    kwargs.setdefault("token", mock.token)
    t = JiraTracker(base_url=mock.url, project=mock.project,
                    sleep=sleeps.append, **kwargs)
    return t, sleeps


def file_args(mock: MockJira, ledger, *extra: str) -> list[str]:
    return ["file", "--ledger", str(ledger), "--tracker", "jira",
            "--url", mock.url, "--project", mock.project,
            "--email", mock.email, "--token", mock.token, *extra]


def seed(tmp_path):
    ledger = tmp_path / "ledger.json"
    assert main(["ingest", str(FIXTURES / "run1.json"), "--ledger", str(ledger)]) == 0
    return ledger


# ---- backend over real HTTP -------------------------------------------------

def test_create_then_update_round_trip(jira):
    t, _ = tracker_for(jira)
    t.preflight()
    res = t.create_issue("[SL-0001] (high) XSS", "wiki body", ["secledger", "sev:high"])

    assert res == {"ref": "SEC-1", "url": f"{jira.url}/browse/SEC-1"}
    assert jira.issues["SEC-1"]["priority"] == {"name": "High"}

    t.update_issue("SEC-1", "ignored", "new body", ["secledger"])
    assert jira.issues["SEC-1"]["description"] == "new body"
    assert jira.issues["SEC-1"]["labels"] == ["secledger"]
    assert jira.issues["SEC-1"]["summary"] == "[SL-0001] (high) XSS"


def test_data_center_bearer_token_works(jira):
    t, _ = tracker_for(jira, email="")
    t.preflight()


def test_retry_after_header_survives_the_real_transport(jira):
    jira.queue_fault(429, headers={"Retry-After": "7"})
    t, sleeps = tracker_for(jira)
    assert t.create_issue("a", "b", [])["ref"] == "SEC-1"
    assert sleeps == [7.0]
    assert jira.count("POST", "/issue") == 2
    assert len(jira.issues) == 1


def test_project_without_priority_still_gets_its_tickets(jira):
    jira.allow_priority = False
    t, _ = tracker_for(jira)
    assert t.create_issue("a", "b", ["sev:critical"])["ref"] == "SEC-1"
    assert t.create_issue("c", "d", ["sev:high"])["ref"] == "SEC-2"
    assert "priority" not in jira.issues["SEC-1"]
    assert jira.count("POST", "/issue") == 3  # one rejected, then two created


def test_gateway_error_on_create_is_not_resent(jira):
    jira.queue_fault(504)
    t, sleeps = tracker_for(jira)
    with pytest.raises(JiraError):
        t.create_issue("a", "b", [])
    assert jira.count("POST", "/issue") == 1 and sleeps == []


def test_unreachable_server_is_a_tracker_error():
    t = JiraTracker(base_url="http://127.0.0.1:9", project="SEC", token="t",
                    max_retries=0, sleep=lambda s: None)
    with pytest.raises(JiraError) as exc:
        t.preflight()
    assert "no response" in str(exc.value)


# ---- CLI --------------------------------------------------------------------

def test_cli_files_each_entry_once(jira, tmp_path, capsys):
    ledger = seed(tmp_path)

    assert main(file_args(jira, ledger)) == 0
    assert sorted(jira.issues) == ["SEC-1", "SEC-2"]
    out = capsys.readouterr().out
    assert f"{jira.url}/browse/SEC-1" in out and "created=2" in out

    stamps = {e["ledger_id"]: e["trackers"]["jira"] for e in json.loads(ledger.read_text())}
    assert stamps["SL-0001"]["ref"] == "SEC-1"

    # Second run: nothing new is created.
    assert main(file_args(jira, ledger)) == 0
    assert jira.count("POST", "/issue") == 2
    assert "skipped=2" in capsys.readouterr().out


def test_cli_sends_wiki_markup_not_markdown(jira, tmp_path):
    ledger = seed(tmp_path)
    main(file_args(jira, ledger, "--issue-type", "Bug"))
    fields = jira.issues["SEC-1"]
    assert fields["issuetype"] == {"name": "Bug"}
    assert "h3. Finding" in fields["description"]
    assert "{noformat}" in fields["description"]
    assert "| --- |" not in fields["description"]
    assert not any(" " in label for label in fields["labels"])


def test_cli_min_severity_and_dry_run(jira, tmp_path, capsys):
    ledger = seed(tmp_path)
    assert main(file_args(jira, ledger, "--min-severity", "high", "--dry-run")) == 0
    assert jira.requests == []  # dry run never touches Jira, preflight included
    assert capsys.readouterr().out.count("WOULD-CREATE") == 1

    assert main(file_args(jira, ledger, "--min-severity", "high")) == 0
    assert len(jira.issues) == 1


def test_cli_bad_token_stops_before_creating_anything(jira, tmp_path, capsys):
    ledger = seed(tmp_path)
    args = file_args(jira, ledger)
    args[args.index("--token") + 1] = "wrong"

    assert main(args) == 1
    assert "authentication failed" in capsys.readouterr().err
    assert jira.count("POST", "/issue") == 0
    assert all(not e["trackers"] for e in json.loads(ledger.read_text()))


def test_cli_wrong_project_stops_before_creating_anything(jira, tmp_path, capsys):
    ledger = seed(tmp_path)
    args = file_args(jira, ledger)
    args[args.index("--project") + 1] = "NOPE"

    assert main(args) == 1
    assert "HTTP 404" in capsys.readouterr().err
    assert jira.count("POST", "/issue") == 0


def test_cli_reads_connection_from_environment(jira, tmp_path, monkeypatch):
    ledger = seed(tmp_path)
    monkeypatch.setenv("JIRA_URL", jira.url)
    monkeypatch.setenv("JIRA_PROJECT", jira.project)
    monkeypatch.setenv("JIRA_EMAIL", jira.email)
    monkeypatch.setenv("JIRA_TOKEN", jira.token)
    monkeypatch.setenv("JIRA_SET_PRIORITY", "false")

    assert main(["file", "--ledger", str(ledger), "--tracker", "jira"]) == 0
    assert len(jira.issues) == 2
    assert "priority" not in jira.issues["SEC-1"]
