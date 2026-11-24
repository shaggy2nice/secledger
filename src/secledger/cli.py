"""Command-line interface: ``ingest``, ``file``, ``show``, ``trackers``.

    secledger ingest run.json [--ledger ledger.json]
    secledger file --tracker gitlab [--dry-run] [--min-severity high] [--update]
    secledger show [--format md|json]
    secledger trackers

Tracker connection details come from flags or environment variables:

    GitLab:  GITLAB_URL, GITLAB_PROJECT, GITLAB_TOKEN, [GITLAB_TOKEN_TYPE]
    GitHub:  GITHUB_API_URL (default https://api.github.com),
             GITHUB_REPO, GITHUB_TOKEN
    Jira:    JIRA_URL, JIRA_PROJECT (project key), JIRA_TOKEN,
             JIRA_EMAIL (Jira Cloud; leave unset for a Data Center token),
             [JIRA_TOKEN_TYPE], [JIRA_ISSUE_TYPE], [JIRA_SET_PRIORITY]
    Any:     SECLEDGER_CA_BUNDLE  (CA file for a self-hosted instance)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .ledger import Ledger, render_ledger_markdown
from .models import Finding, Run, SEVERITIES
from .schema import SchemaError, validate_document
from .filer import file_ledger
from .trackers import available, get_tracker_class
from .trackers.base import TrackerError

DEFAULT_LEDGER = os.environ.get("SECLEDGER_LEDGER", "ledger.json")


def _run_count(ledger: Ledger) -> int:
    runs: set[str] = set()
    for e in ledger:
        for a in e.aliases:
            if a.run:
                runs.add(a.run)
    return len(runs)


def _write_markdown(ledger: Ledger, ledger_path: Path) -> None:
    md = render_ledger_markdown(ledger, run_count=_run_count(ledger))
    (ledger_path.parent / "LEDGER.md").write_text(md)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger)
    try:
        raw = sys.stdin.read() if args.findings == "-" else Path(args.findings).read_text()
        doc = json.loads(raw)
        validate_document(doc)
    except (OSError, json.JSONDecodeError) as exc:
        src = "stdin" if args.findings == "-" else args.findings
        print(f"error reading {src}: {exc}", file=sys.stderr)
        return 1
    except SchemaError as exc:
        print(f"invalid findings document: {exc}", file=sys.stderr)
        return 1

    run = Run.from_dict(doc["run"])
    findings = [Finding.from_dict(f) for f in doc["findings"]]

    ledger = Ledger.load(ledger_path)
    result = ledger.merge_run(run, findings)
    ledger.save(ledger_path)
    _write_markdown(ledger, ledger_path)

    for e in result.new_entries:
        print(f"NEW {e.ledger_id} [{e.severity}] {e.title}")
    print(
        f"run {run.id}: {len(findings)} findings -> "
        f"{len(result.new_entries)} new, {len(result.updated_entries)} merged, "
        f"{len(ledger)} distinct total"
    )
    return 0


def _build_tracker(args: argparse.Namespace):
    name = args.tracker
    cls = get_tracker_class(name)
    ca = args.ca_bundle or os.environ.get("SECLEDGER_CA_BUNDLE")
    extra: dict = {}

    if name == "gitlab":
        base = args.url or os.environ.get("GITLAB_URL", "https://gitlab.com")
        project = args.project or os.environ.get("GITLAB_PROJECT", "")
        token = args.token or os.environ.get("GITLAB_TOKEN", "")
        token_type = args.token_type or os.environ.get("GITLAB_TOKEN_TYPE", "token")
    elif name == "github":
        base = args.url or os.environ.get("GITHUB_API_URL", cls.DEFAULT_BASE_URL)
        project = args.project or os.environ.get("GITHUB_REPO", "")
        token = args.token or os.environ.get("GITHUB_TOKEN", "")
        token_type = args.token_type or "bearer"
    elif name == "jira":
        base = args.url or os.environ.get("JIRA_URL", "")
        project = args.project or os.environ.get("JIRA_PROJECT", "")
        token = args.token or os.environ.get("JIRA_TOKEN", "")
        email = args.email or os.environ.get("JIRA_EMAIL", "")
        # Jira Cloud signs in with email + API token (basic); Data Center
        # with a personal access token (bearer).
        token_type = (
            args.token_type
            or os.environ.get("JIRA_TOKEN_TYPE")
            or ("basic" if email else "bearer")
        )
        extra = {
            "email": email,
            "issue_type": args.issue_type or os.environ.get("JIRA_ISSUE_TYPE", "Task"),
            "set_priority": os.environ.get("JIRA_SET_PRIORITY", "true").strip().lower()
            not in ("false", "0", "no", "off"),
        }
    else:  # pragma: no cover - future backends supply their own defaults
        base = args.url or ""
        project = args.project or ""
        token = args.token or ""
        token_type = args.token_type or "token"

    return cls(
        base_url=base,
        project=project,
        token=token,
        token_type=token_type,
        ca_bundle=ca,
        **extra,
    )


def cmd_file(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger)
    ledger = Ledger.load(ledger_path)
    if len(ledger) == 0:
        print("ledger is empty — nothing to file (run `secledger ingest` first)")
        return 0

    try:
        tracker = _build_tracker(args)
    except TrackerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.dry_run and not tracker.token:
        print(
            f"error: no token for {tracker.name}; set the token env var or pass --token "
            f"(or use --dry-run)",
            file=sys.stderr,
        )
        return 1

    if not args.dry_run:
        # Fail once, before anything is created, if the connection is wrong.
        try:
            tracker.preflight()
        except TrackerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    outcomes = file_ledger(
        ledger,
        tracker,
        min_severity=args.min_severity,
        update=args.update,
        dry_run=args.dry_run,
        on_change=lambda: ledger.save(ledger_path),
    )

    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.action] = counts.get(o.action, 0) + 1
        label = o.action.upper()
        tail = f" -> {o.url}" if o.url else ""
        if o.error:
            tail = f": {o.error}"
        print(f"  {label:<13} {o.ledger_id}{tail}")

    if not args.dry_run:
        _write_markdown(ledger, ledger_path)
    summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"\n{summary or 'nothing to do'}")
    return 1 if counts.get("failed") else 0


def cmd_show(args: argparse.Namespace) -> int:
    ledger = Ledger.load(Path(args.ledger))
    if args.format == "json":
        print(json.dumps([e.to_dict() for e in ledger.sorted_by_id()], indent=2))
    else:
        print(render_ledger_markdown(ledger, run_count=_run_count(ledger)))
    return 0


def cmd_trackers(args: argparse.Namespace) -> int:
    for name in available():
        print(name)
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secledger",
        description="Deterministic, idempotent security-findings ledger and "
        "issue filer.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("ingest", help="merge a scanner run into the ledger")
    sp.add_argument("findings", help="findings JSON document, or '-' for stdin")
    sp.add_argument("--ledger", default=DEFAULT_LEDGER, help="ledger.json path")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("file", help="file ledger entries into a tracker")
    sp.add_argument("--ledger", default=DEFAULT_LEDGER, help="ledger.json path")
    sp.add_argument("--tracker", required=True, choices=available())
    sp.add_argument("--url", help="tracker base URL (else per-tracker env var)")
    sp.add_argument("--project", help="project id/path or owner/repo (else env)")
    sp.add_argument("--token", help="access token (else per-tracker env var)")
    sp.add_argument("--token-type", help="token / bearer (jira: basic / bearer)")
    sp.add_argument("--email", help="jira: account email for Jira Cloud (else JIRA_EMAIL)")
    sp.add_argument("--issue-type", help="jira: issue type name (default: Task)")
    sp.add_argument("--ca-bundle", help="CA file for a self-hosted instance")
    sp.add_argument("--min-severity", choices=list(SEVERITIES),
                    help="file this severity and above (default: all)")
    sp.add_argument("--update", action="store_true",
                    help="refresh changed bodies of already-filed entries")
    sp.add_argument("--dry-run", action="store_true",
                    help="print what would be filed; make no API calls")
    sp.set_defaults(func=cmd_file)

    sp = sub.add_parser("show", help="print the ledger")
    sp.add_argument("--ledger", default=DEFAULT_LEDGER, help="ledger.json path")
    sp.add_argument("--format", choices=["md", "json"], default="md")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("trackers", help="list available tracker backends")
    sp.set_defaults(func=cmd_trackers)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
