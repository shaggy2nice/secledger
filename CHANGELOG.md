# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Tracker backend: **Jira** (Cloud and Data Center, REST API v2). Email + API
  token or personal access token auth, severity → priority with a fallback for
  projects that reject the field, `Retry-After`-aware retries that never
  re-send a create after a timeout or gateway error, and plain-language error
  messages. New `file` options `--email` and `--issue-type`.
- Jira wiki-markup body renderer (`render.issue_body_jira`). A tracker's
  `markup` attribute selects the renderer.
- `Tracker.preflight()` hook: an optional connection check that `file` runs
  once before creating anything.
- `tests/mock_jira.py`: a loopback mock of the Jira endpoints, used by the
  end-to-end tests and runnable as a local sandbox.

### Changed
- A transport may return the response headers as a third element. The default
  `urllib` transport now does; two-element transports keep working.

## [0.1.0] — unreleased

Initial release.

### Added
- Tool-agnostic findings schema (`run` + `findings`) with light validation.
- Cross-run ledger with deterministic signature dedup, `fingerprint` override,
  per-run aliases, severity escalation, and confirmed-status promotion.
- Idempotent issue filing with per-tracker stamping (`ref` + body hash) and
  save-after-each-success.
- Tracker backends: **GitLab** and **GitHub**, over a pluggable `Tracker`
  interface with an injectable HTTP transport (stdlib `urllib`).
- CLI: `ingest` (accepts `-` for stdin), `file` (`--dry-run` /
  `--min-severity` / `--update`), `show`, `trackers`.
- Scanner adapters (`secledger-adapt`): **Semgrep**, **Trivy**, and **OWASP
  ZAP** → findings schema, pipe-friendly and schema-validated, over a small
  registry you can extend.
- Full unit-test suite (signature, ledger, render, trackers, filer, CLI,
  adapters) with synthetic fixtures only; GitHub Actions CI across Python
  3.9–3.12.
