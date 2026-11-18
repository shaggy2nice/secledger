"""GitHub Issues backend (github.com or GitHub Enterprise Server).

API: ``POST /repos/:owner/:repo/issues`` and ``PATCH .../issues/:number``.
``project`` is ``owner/repo``. Auth is a token sent as
``Authorization: Bearer`` (fine-grained or classic PAT, or a GitHub App /
Actions token).

Bodies are GitHub-Flavored Markdown, sent verbatim. Labels referenced here
should already exist on the repo; GitHub silently ignores unknown labels on
issue creation rather than creating them.
"""
from __future__ import annotations

from typing import Any

from .base import Tracker, TrackerError


class GitHubTracker(Tracker):
    name = "github"

    # GitHub's public API base is api.github.com; Enterprise Server is
    # https://<host>/api/v3. Both are passed in as base_url.
    DEFAULT_BASE_URL = "https://api.github.com"

    def auth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _repo(self) -> str:
        if self.project.count("/") != 1:
            raise TrackerError(
                f"github: project must be 'owner/repo', got {self.project!r}"
            )
        return self.project.strip("/")

    def _issues_url(self, suffix: str = "") -> str:
        return f"{self.base_url}/repos/{self._repo()}/issues{suffix}"

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        payload = {"title": title, "body": body, "labels": labels}
        res = self.request("POST", self._issues_url(), payload)
        return {"ref": res.get("number"), "url": res.get("html_url")}

    def update_issue(self, ref: Any, title: str, body: str, labels: list[str]) -> None:
        payload = {"body": body, "labels": labels}
        self.request("PATCH", self._issues_url(f"/{ref}"), payload)
