# Contributing to secledger

Thanks for your interest! secledger aims to stay small, dependency-free, and
easy to audit. Contributions that keep it that way are very welcome.

## Development setup

```bash
git clone <your-fork>
cd secledger
pip install -e ".[dev]"
pytest
```

No runtime dependencies are allowed in the core package — it must run on a
clean Python 3.9+ with only the standard library. Test-only and dev tooling
go under `[project.optional-dependencies].dev`.

## Guidelines

- **Keep the core stdlib-only.** If a feature seems to need a dependency,
  open an issue first so we can discuss an alternative.
- **Backends are small and tested.** Every tracker backend ships with unit
  tests that drive it through a fake transport (see `tests/conftest.py`) — no
  live network in the test suite.
- **No real data in fixtures.** Everything under `tests/fixtures/` and
  `examples/` must be synthetic. Never commit real findings, hostnames, tokens,
  or any third party's data.
- **Deterministic output.** Rendered issue bodies and signatures must be
  deterministic — the idempotency guarantees depend on it.

## Adding a tracker

1. Subclass `secledger.trackers.base.Tracker`, implement `auth_headers`,
   `create_issue`, and `update_issue`.
2. `register` it in `secledger/trackers/__init__.py`.
3. Add CLI env/default wiring in `cli.py:_build_tracker`.
4. Add tests driving it through `FakeTransport`. (Jira also has end-to-end
   tests against `tests/mock_jira.py`, which listens on loopback only.)
5. Update the trackers table in the README.

## Reporting security issues

Please report vulnerabilities in secledger itself privately to the maintainer
rather than opening a public issue.
