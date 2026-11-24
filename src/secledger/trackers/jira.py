"""Jira backend (Jira Cloud, or Jira Data Center / Server).

API: ``POST /rest/api/2/issue`` and ``PUT /rest/api/2/issue/:key``. REST v2 is
used because Cloud and Data Center both serve it and both take the
description as wiki markup, so one backend covers both. ``project`` is the
project key (``SEC``).

Auth, chosen by ``token_type``:

* ``basic``  — Jira Cloud: account ``email`` + API token, sent as HTTP Basic.
* ``bearer`` — Data Center / Server personal access token.

Left unset it is ``basic`` when an email is given and ``bearer`` otherwise.

What this backend does beyond the simpler ones:

* **Preflight.** Credentials and project are checked once before the first
  create, so a wrong token is one clear error instead of one per finding.
* **Retries that cannot duplicate.** A create is retried only when Jira says
  it did not process the request (429, 503), waiting at least ``Retry-After``.
  A timeout, dropped connection, 502 or 504 is reported instead: the issue may
  already exist, and sending the POST again would file it twice.
* **Priority.** The ``sev:<severity>`` label maps to Jira's default priority
  names. A project that rejects the field is detected on the first create and
  the rest of the run goes without it.
* **Labels.** Jira labels cannot contain whitespace; it becomes ``-``.

Bodies come from ``secledger.render.issue_body_jira`` (``markup = "jira"``).
As with the other backends, an update replaces the issue's description and
label set and leaves the title alone.
"""
from __future__ import annotations

import base64
import http.client
import json
import time
import urllib.parse
from typing import Any, Callable

from .base import Tracker, TrackerError

# secledger severity -> Jira's default priority names.
PRIORITY_BY_SEVERITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

SUMMARY_MAX = 255  # Jira rejects longer summaries.

# Statuses worth retrying; see the module docstring for why a create is
# stricter than a read or an update.
RETRY_CREATE = frozenset({429, 503})
RETRY_IDEMPOTENT = frozenset({429, 502, 503, 504})

# Longest single wait. A Retry-After beyond this fails the call (with the
# wait in the message) rather than stalling a pipeline for an hour.
MAX_RETRY_DELAY = 60.0

_HINTS = {
    400: "Jira rejected the request; a required field may be missing or a "
         "value may not be allowed in this project",
    401: "authentication failed; check the token (and the account email for "
         "Jira Cloud)",
    403: "access denied; the account may lack permission in this project",
    404: "not found; check the base URL and the project key",
    429: "rate limited by Jira",
}


class JiraError(TrackerError):
    """A Jira API call failed. ``status`` is the HTTP status (0 = no response)."""

    def __init__(self, message: str, status: int = 0, body: dict | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body or {}


class JiraTracker(Tracker):
    name = "jira"
    markup = "jira"

    def __init__(
        self,
        *,
        email: str = "",
        issue_type: str = "Task",
        set_priority: bool = True,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("token_type", "basic" if email else "bearer")
        super().__init__(**kwargs)
        if self.token_type not in ("basic", "bearer"):
            raise TrackerError(
                "jira: token_type must be 'basic' (Jira Cloud: email + API "
                "token) or 'bearer' (Data Center personal access token)"
            )
        if self.token_type == "basic" and not email:
            raise TrackerError("jira: basic auth needs the account email")
        self.project = self.project.strip().upper()  # Jira keys are uppercase
        self.email = email
        self.issue_type = issue_type or "Task"
        self.set_priority = set_priority
        self.max_retries = max_retries
        self._sleep = sleep

    # ---- helpers ---------------------------------------------------------

    def auth_headers(self) -> dict:
        if self.token_type == "basic":
            raw = f"{self.email}:{self.token}".encode("utf-8")
            return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
        return {"Authorization": f"Bearer {self.token}"}

    def _api(self, path: str) -> str:
        return f"{self.base_url}/rest/api/2{path}"

    def request(self, method: str, url: str, payload: dict | None = None) -> dict:
        headers = {"Accept": "application/json", **self.auth_headers()}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        is_create = method == "POST"
        retryable = RETRY_CREATE if is_create else RETRY_IDEMPOTENT

        attempt = 0
        while True:
            attempt += 1
            may_retry = attempt <= self.max_retries
            try:
                result = self._transport(method, url, headers, body)
            except (OSError, http.client.HTTPException) as exc:
                # Timeout, DNS, refused connection, TLS: no HTTP response.
                if not is_create and may_retry:
                    self._sleep(_backoff(attempt))
                    continue
                raise JiraError(_no_response(method, url, exc, is_create)) from exc

            status, raw = result[0], result[1]
            wait = _retry_after(result[2] if len(result) > 2 else None)
            if status in retryable and may_retry and (wait or 0) <= MAX_RETRY_DELAY:
                # Retry-After is the minimum wait; the delay doubles per retry.
                self._sleep(max(wait or 0.0, _backoff(attempt)))
                continue
            if status >= 400:
                err = _error_body(raw)
                raise JiraError(_explain(status, method, url, err, raw, wait), status, err)
            if not raw.strip():
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise JiraError(f"jira: non-JSON response: {exc}", status) from exc

    # ---- backend contract ------------------------------------------------

    def preflight(self) -> None:
        """Check the credentials and the project before anything is created."""
        self.request("GET", self._api("/myself"))
        self.request("GET", self._api("/project/" + urllib.parse.quote(self.project, safe="")))

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        fields: dict[str, Any] = {
            "project": {"key": self.project},
            "issuetype": {"name": self.issue_type},
            "summary": _summary(title),
            "description": body,
            "labels": _labels(labels),
        }
        priority = _priority(labels) if self.set_priority else None
        if priority:
            fields["priority"] = {"name": priority}
        try:
            res = self.request("POST", self._api("/issue"), {"fields": fields})
        except JiraError as exc:
            # Jira names the field it refused (400 + errors.priority) and
            # creates nothing, so dropping priority and sending once more
            # cannot duplicate. Remembered for the rest of the run.
            errors = exc.body.get("errors")
            if not (priority and exc.status == 400
                    and isinstance(errors, dict) and "priority" in errors):
                raise
            self.set_priority = False
            del fields["priority"]
            res = self.request("POST", self._api("/issue"), {"fields": fields})
        key = res.get("key")
        return {"ref": key, "url": f"{self.base_url}/browse/{key}" if key else ""}

    def update_issue(self, ref: Any, title: str, body: str, labels: list[str]) -> None:
        payload = {"fields": {"description": body, "labels": _labels(labels)}}
        url = self._api("/issue/" + urllib.parse.quote(str(ref), safe=""))
        self.request("PUT", url, payload)


# --------------------------------------------------------------------------
# field shaping
# --------------------------------------------------------------------------

def _summary(title: str) -> str:
    """A Jira summary is one line of at most 255 characters."""
    return " ".join(title.split())[:SUMMARY_MAX]


def _labels(labels: list[str]) -> list[str]:
    out: list[str] = []
    for label in labels:
        clean = "-".join(label.split())
        if clean and clean not in out:
            out.append(clean)
    return out


def _priority(labels: list[str]) -> str | None:
    for label in labels:
        if label.startswith("sev:"):
            return PRIORITY_BY_SEVERITY.get(label[4:].strip().lower())
    return None


# --------------------------------------------------------------------------
# retries and errors
# --------------------------------------------------------------------------

def _backoff(attempt: int) -> float:
    return min(float(2 ** (attempt - 1)), MAX_RETRY_DELAY)  # 1, 2, 4, ...


def _retry_after(headers: Any) -> float | None:
    """Seconds from a ``Retry-After`` header, or None if absent or a date."""
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() == "retry-after":
            try:
                return max(0.0, float(str(value).strip()))
            except ValueError:
                return None
    return None


def _error_body(raw: bytes) -> dict:
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _explain(status: int, method: str, url: str, err: dict, raw: bytes,
             wait: float | None) -> str:
    """Jira's error response as one plain-language line."""
    message = f"jira: HTTP {status} for {method} {url}"
    hint = _HINTS.get(status)
    if hint:
        message += f": {hint}"
    if status == 429 and wait:
        message += f" (asked to wait {wait:g}s)"

    details: list[str] = []
    messages = err.get("errorMessages")
    if isinstance(messages, list):
        details += [str(m) for m in messages]
    errors = err.get("errors")
    if isinstance(errors, dict):
        details += [f"{field}: {text}" for field, text in errors.items()]
    if not details and not hint:
        snippet = raw.decode("utf-8", "replace").strip()[:300]
        if snippet:
            details.append(snippet)
    if details:
        message += " [" + "; ".join(details) + "]"
    return message


def _no_response(method: str, url: str, exc: BaseException, is_create: bool) -> str:
    message = f"jira: no response for {method} {url}: {exc}"
    if is_create:
        message += (
            ". The issue may or may not have been created; check Jira before "
            "re-running, or the next run can file it a second time"
        )
    return message
