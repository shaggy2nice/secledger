# secledger
[![CI](https://github.com/shaggy2nice/secledger/actions/workflows/ci.yml/badge.svg)](https://github.com/shaggy2nice/secledger/actions/workflows/ci.yml)

**A deterministic, idempotent ledger for security findings — and a safe way to file them into your issue tracker.**

Security scanners are noisy and they repeat themselves. Run the same DAST,
SAST, or pentest tooling next week and you get the same findings again, worded
slightly differently. `secledger` sits between your scanners and your tracker
and does two boring-but-essential things well:

1. **Ledger** — collapse findings across every run into one stable entry per
   distinct issue, with first-seen / last-seen / times-seen and per-run
   history. Re-ingesting the same run is a no-op.
2. **File** — open exactly one tracker issue per distinct finding, stamp the
   issue id back into the ledger, and never double-file. Re-run as often as
   you like.

It's **pure standard library** (no third-party dependencies), so it drops
cleanly into locked-down and air-gapped environments. Findings come in as a
small, tool-agnostic JSON shape, so **any** scanner can feed it.

```
scanner run ─► findings.json ─► secledger ingest ─► ledger.json ─► secledger file ─► GitLab / GitHub issues
                                      (dedupe)                         (idempotent)
```

---

## Install

```bash
pip install secledger          # once published
# or, from a clone:
pip install -e .
```

Python 3.9+. No runtime dependencies.

## Quickstart

```bash
# 1. Merge a scanner run into the ledger (idempotent; safe to re-run).
secledger ingest examples/findings.sample.json --ledger ledger.json

# 2. See what you've got.
secledger show --ledger ledger.json

# 3. File issues — preview first.
export GITLAB_URL=https://gitlab.example.mil
export GITLAB_PROJECT=team/app            # numeric id or full path
export GITLAB_TOKEN=glpat-xxxxxxxx        # scope: api
secledger file --tracker gitlab --dry-run
secledger file --tracker gitlab --min-severity medium

# 4. Next week, after another scan: ingest again, file again. No duplicates.
secledger ingest next-run.json
secledger file --tracker gitlab --update      # refresh any changed bodies
```

## The findings schema

One scanner run is one JSON document. Only `run.id` and each finding's `id`
are required; everything else is optional.

```json
{
  "schema_version": "1.0",
  "run": { "id": "2026-03-15T14-30-00Z", "scanner": "my-scanner", "target": "dev.example.app" },
  "findings": [
    {
      "id": "finding-1",
      "title": "Server-side request forgery in webhook test endpoint",
      "severity": "high",                 // critical | high | medium | low | info
      "category": "ssrf",
      "location": "POST /api/webhooks:test",
      "description": "markdown body ...",
      "status": "confirmed",              // optional; "confirmed"/"verified" promote the entry
      "references": ["CWE-918"],
      "fingerprint": "osv:CVE-2025-0:lib", // optional; exact dedup when present
      "extra": {}                          // optional passthrough
    }
  ]
}
```

Write a tiny adapter from your scanner's native output to this shape and you're
done. See [`examples/findings.sample.json`](examples/findings.sample.json).

## Adapters (scanner → schema)

Shipped converters turn a scanner's native JSON into the findings schema, so you
can go from a scan to filed issues without writing any glue:

```bash
secledger-adapt <scanner> [input.json] [-o out.json] [--run-id ID] [--target NAME]
```

Reads stdin / writes stdout by default, so it pipes straight into `ingest`:

```bash
semgrep --json -o - .            | secledger-adapt semgrep --target dev | secledger ingest -
trivy image --format json app:ci | secledger-adapt trivy   --target ci  | secledger ingest -
# (ZAP writes a file) :
secledger-adapt zap zap-report.json --target staging | secledger ingest -
```

| Adapter | Source | Notes |
| --- | --- | --- |
| `semgrep` | `semgrep --json` | passes through Semgrep's stable `fingerprint` for exact dedup |
| `trivy` | `trivy --format json` | `Vulnerabilities` → `pkg@version`, keyed on `CVE:pkg`; marked `confirmed` |
| `zap` | OWASP ZAP JSON report | one finding per alert; no fingerprint, so `category::location` dedupes per endpoint |

These are deliberately small (~40 lines each in
[`src/secledger/adapters/`](src/secledger/adapters/)) — copy the closest one for
your scanner. Each adapter validates its output against the schema before
emitting it, so a broken mapping fails loudly.

**Writing your own** is a ~30-line function; see the step-by-step guide in
[`src/secledger/adapters/README.md`](src/secledger/adapters/README.md),
including the one real design decision (exact `fingerprint` dedup vs
`category::location` merging) and how to register and test it.

## How dedup works

Each finding gets a **signature** — the stable key that decides sameness:

- If the scanner supplied a `fingerprint`, the signature is `fp::<fingerprint>`
  (exact). This is the recommended path for tools that emit stable fingerprints.
- Otherwise it's `category :: normalized(location)`, where normalization folds
  away scheme+host, query strings, a leading HTTP method, a trailing `:line`,
  duplicate slashes, and case — so `GET https://h/search?q=1` and
  `https://h/search` collapse to one entry.

The signature is a **deterministic text key, not a semantic judge**: it can
over-merge two different bugs that share a category+location, or split one bug
described at two locations. Treat a `NEW` line as "look at this", and skim
merges before trusting them. Need different behavior? The strategy is one
function — see [Extending](#extending).

## Idempotency & re-runs

- **`ingest`** keys on `(run id, finding id)`. Re-ingesting a run changes
  nothing.
- **`file`** stamps `trackers.<name> = {ref, url, body_sha256}` into each
  ledger entry. An entry that already has a `ref` is never re-created; with
  `--update`, an entry whose freshly rendered body hashes the same is skipped,
  so the pass is a no-op when nothing changed. The ledger is saved after every
  successful API call, so an interrupted run never re-files what already landed.

Because the stamp is keyed by tracker name, one ledger can be filed into
several trackers at once without collision.

## Trackers

| Tracker | `--project` | Token env | Notes |
| --- | --- | --- | --- |
| `gitlab` | numeric id or `group/sub/project` | `GITLAB_TOKEN` | `GITLAB_URL` for self-hosted; `GITLAB_TOKEN_TYPE=bearer` for OAuth |
| `github` | `owner/repo` | `GITHUB_TOKEN` | `GITHUB_API_URL` for Enterprise Server |

Self-hosted instance with a private/enterprise CA? Point `SECLEDGER_CA_BUNDLE`
(or `--ca-bundle`) at the CA chain.

```bash
secledger trackers        # list available backends
```

## Extending

Add a tracker by subclassing `Tracker` and registering it:

```python
from secledger.trackers.base import Tracker
from secledger.trackers import register

@register
class MyTracker(Tracker):
    name = "mytracker"
    def auth_headers(self): return {"Authorization": f"Bearer {self.token}"}
    def create_issue(self, title, body, labels):
        res = self.request("POST", f"{self.base_url}/issues",
                           {"title": title, "body": body, "labels": labels})
        return {"ref": res["id"], "url": res["url"]}
    def update_issue(self, ref, title, body, labels):
        self.request("PATCH", f"{self.base_url}/issues/{ref}",
                     {"body": body, "labels": labels})
```

Swap the dedup strategy with `secledger.signature.set_default_strategy(fn)`.

> **Roadmap:** a Jira backend is a natural next contribution — the `Tracker`
> interface is ready for it. PRs welcome.

## Security notes

- Tokens are read from the environment (or `--token`) and are never written to
  the ledger or printed.
- The ledger stores finding **metadata** (titles, categories, locations,
  severities) and your issue bodies — treat `ledger.json` and `LEDGER.md` with
  the same sensitivity as the findings themselves.
- No telemetry, no network calls except to the tracker you configure.

## Development

```bash
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). © 2026 Harrison "Taylor" Parsons.
