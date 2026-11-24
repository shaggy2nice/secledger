"""A small in-process mock of the Jira REST v2 endpoints secledger uses.

It serves ``/myself``, ``/project/:key``, ``POST /issue`` and
``PUT /issue/:key`` on a loopback port, applies the validation rules the Jira
backend has to cope with (auth, unknown project, labels with spaces, a project
that rejects ``priority``), and lets a test queue faults such as a 429 with
``Retry-After``. Everything in it is synthetic.

Tests use it as a context manager::

    with MockJira() as jira:
        tracker = JiraTracker(base_url=jira.url, project="SEC",
                              email=jira.email, token=jira.token)

It also runs standalone, as a sandbox for trying the Jira backend without a
Jira site::

    python tests/mock_jira.py --port 8089
"""
from __future__ import annotations

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = "/rest/api/2"


class MockJira:
    def __init__(
        self,
        *,
        project: str = "SEC",
        email: str = "bot@example.test",
        token: str = "mock-token",
        allow_priority: bool = True,
        port: int = 0,
    ) -> None:
        self.project = project
        self.email = email
        self.token = token
        self.allow_priority = allow_priority
        self.issues: dict[str, dict] = {}   # key -> fields as last written
        self.requests: list[tuple[str, str]] = []  # (method, path), in order
        self._faults: list[tuple[str, int, dict, dict]] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        # A short poll interval keeps stop() from adding half a second per test.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    # ---- lifecycle -------------------------------------------------------

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "MockJira":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "MockJira":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---- test controls ---------------------------------------------------

    def queue_fault(self, status: int, *, method: str = "POST",
                    headers: dict | None = None, body: dict | None = None) -> None:
        """Answer the next ``method`` request with this response instead."""
        with self._lock:
            self._faults.append((method, status, headers or {}, body or {}))

    def count(self, method: str, path_suffix: str = "") -> int:
        return sum(1 for m, p in self.requests if m == method and p.endswith(path_suffix))

    # ---- request handling ------------------------------------------------

    def _authorized(self, header: str) -> bool:
        basic = base64.b64encode(f"{self.email}:{self.token}".encode()).decode()
        return header in (f"Basic {basic}", f"Bearer {self.token}")

    def _take_fault(self, method: str):
        with self._lock:
            for i, fault in enumerate(self._faults):
                if fault[0] == method:
                    return self._faults.pop(i)
        return None

    def _create(self, payload: dict):
        fields = payload.get("fields") or {}
        errors: dict[str, str] = {}
        if (fields.get("project") or {}).get("key") != self.project:
            errors["project"] = "valid project is required"
        summary = fields.get("summary") or ""
        if not summary.strip():
            errors["summary"] = "You must specify a summary of the issue."
        elif len(summary) > 255 or "\n" in summary:
            errors["summary"] = "Summary must be one line of at most 255 characters."
        for label in fields.get("labels") or []:
            if any(ch.isspace() for ch in label):
                errors["labels"] = f"The label '{label}' contains spaces which is invalid."
        if "priority" in fields and not self.allow_priority:
            errors["priority"] = (
                "Field 'priority' cannot be set. It is not on the appropriate "
                "screen, or unknown."
            )
        if errors:
            return 400, {"errorMessages": [], "errors": errors}
        with self._lock:
            number = len(self.issues) + 1
            key = f"{self.project}-{number}"
            self.issues[key] = fields
        return 201, {"id": str(10000 + number), "key": key,
                     "self": f"{self.url}{API}/issue/{10000 + number}"}

    def _route(self, method: str, path: str, payload: dict):
        if method == "GET" and path == f"{API}/myself":
            return 200, {"displayName": "Mock User", "emailAddress": self.email}
        if method == "GET" and path.startswith(f"{API}/project/"):
            key = path.rsplit("/", 1)[1]
            if key == self.project:
                return 200, {"key": key, "name": "Mock security project"}
            return 404, {"errorMessages": [f"No project could be found with key '{key}'."],
                         "errors": {}}
        if method == "POST" and path == f"{API}/issue":
            return self._create(payload)
        if method == "PUT" and path.startswith(f"{API}/issue/"):
            key = path.rsplit("/", 1)[1]
            with self._lock:
                if key not in self.issues:
                    return 404, {"errorMessages": ["Issue does not exist."], "errors": {}}
                self.issues[key].update(payload.get("fields") or {})
            return 204, None
        return 404, {"errorMessages": ["Unknown mock endpoint."], "errors": {}}

    def _handler(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def _respond(self, status: int, body, headers: dict | None = None) -> None:
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, str(value))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self) -> None:
                method, path = self.command, self.path.split("?", 1)[0]
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                mock.requests.append((method, path))

                if not mock._authorized(self.headers.get("Authorization", "")):
                    self._respond(401, {"errorMessages": ["You are not authenticated."],
                                        "errors": {}})
                    return
                fault = mock._take_fault(method)
                if fault:
                    self._respond(fault[1], fault[3], fault[2])
                    return
                try:
                    payload = json.loads(raw) if raw else {}
                except ValueError:
                    self._respond(400, {"errorMessages": ["Invalid JSON."], "errors": {}})
                    return
                self._respond(*mock._route(method, path, payload))

            do_GET = do_POST = do_PUT = _handle

            def log_message(self, *args) -> None:  # keep test output quiet
                pass

        return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the mock Jira server.")
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument("--project", default="SEC")
    parser.add_argument("--no-priority", action="store_true",
                        help="reject the priority field, like a project without it")
    args = parser.parse_args()
    mock = MockJira(project=args.project, port=args.port,
                    allow_priority=not args.no_priority).start()
    print(f"mock Jira at {mock.url}  (Ctrl-C to stop)")
    print(f"  export JIRA_URL={mock.url} JIRA_PROJECT={mock.project} "
          f"JIRA_EMAIL={mock.email} JIRA_TOKEN={mock.token}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        mock.stop()


if __name__ == "__main__":
    main()
