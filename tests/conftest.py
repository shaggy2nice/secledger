from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parent.parent / "examples"


class FakeTransport:
    """Records requests and returns canned responses.

    Each response is ``(status_code, payload_dict)``; payloads are JSON-encoded
    back to the caller exactly as a real tracker would return them.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": json.loads(body) if body else None,
            }
        )
        status, payload = self._responses.pop(0)
        return status, json.dumps(payload).encode()


class RecordingTracker:
    """Duck-typed tracker for filer tests — no network, records calls."""

    name = "rec"

    def __init__(self):
        self.created = []
        self.updated = []
        self.token = "test-token"

    def create_issue(self, title, body, labels):
        self.created.append((title, body, list(labels)))
        n = len(self.created)
        return {"ref": n, "url": f"https://tracker.test/issues/{n}"}

    def update_issue(self, ref, title, body, labels):
        self.updated.append((ref, title, body, list(labels)))
