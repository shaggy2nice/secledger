# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

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
