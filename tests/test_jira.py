from __future__ import annotations

import base64
import urllib.error

import pytest

from secledger.trackers import JiraError, JiraTracker, available
from secledger.trackers.base import TrackerError

from conftest import FakeTransport

CREATED = (201, {"id": "10001", "key": "SEC-1", "self": "https://jira.test/rest/api/2/issue/10001"})
LABELS = ["secledger", "sev:high", "cat:xss", "sl-0001"]


def make(responses, **kwargs):
    """A Jira Cloud tracker on a fake transport, with sleeps recorded."""
    ft = FakeTransport(responses)
    sleeps: list[float] = []
    kwargs.setdefault("email", "bot@example.test")
    tracker = JiraTracker(base_url="https://jira.test/", project="sec", token="tok",
                          transport=ft, sleep=sleeps.append, **kwargs)
    return tracker, ft, sleeps


def test_registered():
    assert "jira" in available()
    assert JiraTracker.markup == "jira"


# ---- requests ---------------------------------------------------------------

def test_create_builds_correct_request():
    t, ft, _ = make([CREATED])
    res = t.create_issue("[SL-0001] (high) Reflected XSS", "body", LABELS)

    assert res == {"ref": "SEC-1", "url": "https://jira.test/browse/SEC-1"}
    call = ft.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://jira.test/rest/api/2/issue"
    assert call["body"] == {"fields": {
        "project": {"key": "SEC"},          # key is upper-cased
        "issuetype": {"name": "Task"},
        "summary": "[SL-0001] (high) Reflected XSS",
        "description": "body",
        "labels": LABELS,
        "priority": {"name": "High"},
    }}


def test_cloud_auth_is_basic_email_and_token():
    t, ft, _ = make([CREATED])
    t.create_issue("a", "b", [])
    expected = base64.b64encode(b"bot@example.test:tok").decode()
    assert ft.calls[0]["headers"]["Authorization"] == f"Basic {expected}"


def test_data_center_auth_is_bearer_when_no_email():
    t, ft, _ = make([CREATED], email="")
    t.create_issue("a", "b", [])
    assert ft.calls[0]["headers"]["Authorization"] == "Bearer tok"


def test_basic_without_email_and_unknown_token_type_raise():
    with pytest.raises(TrackerError):
        JiraTracker(base_url="https://jira.test", project="SEC", token="t",
                    token_type="basic")
    with pytest.raises(TrackerError):
        JiraTracker(base_url="https://jira.test", project="SEC", token="t",
                    token_type="token")


def test_update_uses_put_and_key_and_leaves_summary_alone():
    t, ft, _ = make([(204, {})])
    t.update_issue("SEC-7", "ignored title", "new body", ["a b", "c"])
    call = ft.calls[0]
    assert call["method"] == "PUT"
    assert call["url"] == "https://jira.test/rest/api/2/issue/SEC-7"
    assert call["body"] == {"fields": {"description": "new body", "labels": ["a-b", "c"]}}


def test_preflight_checks_account_then_project():
    t, ft, _ = make([(200, {"displayName": "Bot"}), (200, {"key": "SEC"})])
    t.preflight()
    assert [c["url"] for c in ft.calls] == [
        "https://jira.test/rest/api/2/myself",
        "https://jira.test/rest/api/2/project/SEC",
    ]


# ---- field shaping ----------------------------------------------------------

def test_summary_is_one_line_and_capped():
    t, ft, _ = make([CREATED])
    t.create_issue("line one\nline two " + "x" * 400, "b", [])
    summary = ft.calls[0]["body"]["fields"]["summary"]
    assert "\n" not in summary and summary.startswith("line one line two")
    assert len(summary) == 255


def test_labels_lose_whitespace_and_duplicates():
    t, ft, _ = make([CREATED])
    t.create_issue("a", "b", ["cat:sql injection", "cat:sql-injection", " ", "ok"])
    assert ft.calls[0]["body"]["fields"]["labels"] == ["cat:sql-injection", "ok"]


@pytest.mark.parametrize("severity,priority", [
    ("critical", "Highest"), ("high", "High"), ("medium", "Medium"),
    ("low", "Low"), ("info", "Lowest"),
])
def test_priority_follows_severity_label(severity, priority):
    t, ft, _ = make([CREATED])
    t.create_issue("a", "b", [f"sev:{severity}"])
    assert ft.calls[0]["body"]["fields"]["priority"] == {"name": priority}


def test_no_priority_without_severity_label_or_when_disabled():
    t, ft, _ = make([CREATED, CREATED], set_priority=False)
    t.create_issue("a", "b", ["sev:high"])
    assert "priority" not in ft.calls[0]["body"]["fields"]

    t, ft, _ = make([CREATED])
    t.create_issue("a", "b", ["no-severity-here"])
    assert "priority" not in ft.calls[0]["body"]["fields"]


def test_priority_rejection_is_detected_once_then_skipped():
    rejected = (400, {"errorMessages": [], "errors": {"priority": "Field 'priority' cannot be set."}})
    second = (201, {"key": "SEC-2"})
    t, ft, _ = make([rejected, CREATED, second])

    assert t.create_issue("a", "b", ["sev:high"])["ref"] == "SEC-1"
    assert "priority" in ft.calls[0]["body"]["fields"]
    assert "priority" not in ft.calls[1]["body"]["fields"]

    # The next create does not try priority again.
    assert t.create_issue("c", "d", ["sev:critical"])["ref"] == "SEC-2"
    assert len(ft.calls) == 3
    assert "priority" not in ft.calls[2]["body"]["fields"]


def test_other_400s_are_not_retried_without_priority():
    bad = (400, {"errorMessages": [], "errors": {"customfield_10010": "Team is required."}})
    t, ft, _ = make([bad])
    with pytest.raises(JiraError) as exc:
        t.create_issue("a", "b", ["sev:high"])
    assert len(ft.calls) == 1
    assert exc.value.status == 400
    assert "customfield_10010: Team is required." in str(exc.value)


# ---- retries ----------------------------------------------------------------

def test_rate_limit_waits_at_least_retry_after_then_succeeds():
    t, ft, sleeps = make([(429, {}, {"Retry-After": "5"}), CREATED])
    assert t.create_issue("a", "b", [])["ref"] == "SEC-1"
    assert sleeps == [5.0]
    assert len(ft.calls) == 2


def test_backoff_doubles_when_no_retry_after():
    t, ft, sleeps = make([(503, {}), (429, {}, {"retry-after": "1"}), (429, {}), CREATED])
    t.create_issue("a", "b", [])
    assert sleeps == [1.0, 2.0, 4.0]


def test_retries_are_bounded():
    t, ft, sleeps = make([(429, {})] * 4)
    with pytest.raises(JiraError) as exc:
        t.create_issue("a", "b", [])
    assert exc.value.status == 429
    assert len(ft.calls) == 4 and len(sleeps) == 3
    assert "rate limited" in str(exc.value)


def test_long_retry_after_fails_fast_and_says_how_long():
    t, ft, sleeps = make([(429, {}, {"Retry-After": "1847"})])
    with pytest.raises(JiraError) as exc:
        t.create_issue("a", "b", [])
    assert sleeps == [] and len(ft.calls) == 1
    assert "1847s" in str(exc.value)


@pytest.mark.parametrize("status", [502, 504])
def test_create_is_not_resent_after_a_gateway_error(status):
    # Jira may have created the issue behind the gateway; a second POST
    # could file a duplicate.
    t, ft, sleeps = make([(status, {})])
    with pytest.raises(JiraError):
        t.create_issue("a", "b", [])
    assert len(ft.calls) == 1 and sleeps == []


def test_create_is_not_resent_after_a_timeout():
    t, ft, sleeps = make([TimeoutError("timed out")])
    with pytest.raises(JiraError) as exc:
        t.create_issue("a", "b", [])
    assert len(ft.calls) == 1 and sleeps == []
    assert exc.value.status == 0
    assert "may or may not have been created" in str(exc.value)


def test_update_is_resent_after_gateway_error_and_dropped_connection():
    t, ft, sleeps = make([(502, {}), urllib.error.URLError("connection reset"), (204, {})])
    t.update_issue("SEC-1", "t", "b", [])
    assert len(ft.calls) == 3
    assert sleeps == [1.0, 2.0]


# ---- errors -----------------------------------------------------------------

@pytest.mark.parametrize("status,hint", [
    (401, "authentication failed"),
    (403, "access denied"),
    (404, "check the base URL and the project key"),
])
def test_errors_are_explained(status, hint):
    t, ft, _ = make([(status, {"errorMessages": ["Jira says no."], "errors": {}})])
    with pytest.raises(TrackerError) as exc:
        t.preflight()
    text = str(exc.value)
    assert f"HTTP {status}" in text and hint in text and "Jira says no." in text


def test_error_message_never_contains_the_token():
    t, ft, _ = make([(401, {"errorMessages": ["nope"]})], email="")
    with pytest.raises(JiraError) as exc:
        t.create_issue("a", "b", [])
    assert "tok" not in str(exc.value).replace("token", "")
