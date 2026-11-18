from __future__ import annotations

import pytest

from secledger.trackers import GitHubTracker, GitLabTracker
from secledger.trackers.base import TrackerError

from conftest import FakeTransport


def test_gitlab_create_builds_correct_request():
    ft = FakeTransport([(201, {"iid": 7, "web_url": "https://gl.test/g/app/-/issues/7"})])
    t = GitLabTracker(base_url="https://gl.test", project="grp/app",
                      token="tok", transport=ft)
    res = t.create_issue("Title", "Body", ["a", "b"])

    assert res == {"ref": 7, "url": "https://gl.test/g/app/-/issues/7"}
    call = ft.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://gl.test/api/v4/projects/grp%2Fapp/issues"
    assert call["headers"]["PRIVATE-TOKEN"] == "tok"
    assert call["body"] == {"title": "Title", "description": "Body", "labels": "a,b"}


def test_gitlab_numeric_project_not_encoded():
    ft = FakeTransport([(201, {"iid": 1, "web_url": "u"})])
    t = GitLabTracker(base_url="https://gl.test", project="123", token="t", transport=ft)
    t.create_issue("a", "b", [])
    assert ft.calls[0]["url"] == "https://gl.test/api/v4/projects/123/issues"


def test_gitlab_update_uses_put_and_iid():
    ft = FakeTransport([(200, {})])
    t = GitLabTracker(base_url="https://gl.test", project="1", token="t", transport=ft)
    t.update_issue(7, "T", "NewBody", ["x"])
    call = ft.calls[0]
    assert call["method"] == "PUT"
    assert call["url"].endswith("/issues/7")
    assert call["body"] == {"description": "NewBody", "labels": "x"}


def test_gitlab_bearer_token():
    ft = FakeTransport([(201, {"iid": 1, "web_url": "u"})])
    t = GitLabTracker(base_url="https://gl.test", project="1", token="oauth",
                      token_type="bearer", transport=ft)
    t.create_issue("a", "b", [])
    assert ft.calls[0]["headers"]["Authorization"] == "Bearer oauth"


def test_github_create_builds_correct_request():
    ft = FakeTransport([(201, {"number": 5, "html_url": "https://gh.test/o/r/issues/5"})])
    t = GitHubTracker(base_url="https://api.github.com", project="o/r",
                      token="tok", token_type="bearer", transport=ft)
    res = t.create_issue("Title", "Body", ["a"])

    assert res == {"ref": 5, "url": "https://gh.test/o/r/issues/5"}
    call = ft.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://api.github.com/repos/o/r/issues"
    assert call["headers"]["Authorization"] == "Bearer tok"
    assert call["body"] == {"title": "Title", "body": "Body", "labels": ["a"]}


def test_github_bad_project_raises():
    t = GitHubTracker(base_url="https://api.github.com", project="not-a-repo",
                      token="t", transport=FakeTransport([]))
    with pytest.raises(TrackerError):
        t.create_issue("a", "b", [])


def test_http_error_raises_trackererror():
    ft = FakeTransport([(403, {"message": "insufficient_scope"})])
    t = GitLabTracker(base_url="https://gl.test", project="1", token="t", transport=ft)
    with pytest.raises(TrackerError) as exc:
        t.create_issue("a", "b", [])
    assert "403" in str(exc.value)


def test_missing_config_raises():
    with pytest.raises(TrackerError):
        GitLabTracker(base_url="", project="1", token="t")
    with pytest.raises(TrackerError):
        GitLabTracker(base_url="https://gl.test", project="", token="t")
