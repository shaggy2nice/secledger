"""GitLab Issues backend (gitlab.com or self-hosted).

API: ``POST /api/v4/projects/:id/issues`` and ``PUT .../issues/:iid``.
``project`` is a numeric id or a full path (``group/sub/project``), which is
URL-encoded for you. Auth is a token sent as ``PRIVATE-TOKEN`` (personal,
project, or group access token) or, when ``token_type="bearer"``, as an OAuth
``Authorization: Bearer``.

Descriptions are GitLab-Flavored Markdown, so the rendered body is sent
verbatim.
"""
from __future__ import annotations

import urllib.parse
from typing import Any

from .base import Tracker


class GitLabTracker(Tracker):
    name = "gitlab"

    def auth_headers(self) -> dict:
        if self.token_type == "bearer":
            return {"Authorization": f"Bearer {self.token}"}
        return {"PRIVATE-TOKEN": self.token}

    def _project_ref(self) -> str:
        p = self.project.strip()
        return p if p.isdigit() else urllib.parse.quote(p, safe="")

    def _issues_url(self, suffix: str = "") -> str:
        return (
            f"{self.base_url}/api/v4/projects/{self._project_ref()}/issues{suffix}"
        )

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        payload = {
            "title": title,
            "description": body,
            "labels": ",".join(labels),
        }
        res = self.request("POST", self._issues_url(), payload)
        return {"ref": res.get("iid"), "url": res.get("web_url")}

    def update_issue(self, ref: Any, title: str, body: str, labels: list[str]) -> None:
        payload = {"description": body, "labels": ",".join(labels)}
        self.request("PUT", self._issues_url(f"/{ref}"), payload)
