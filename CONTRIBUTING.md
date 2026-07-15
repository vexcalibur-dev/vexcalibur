# Contributing

Vexcalibur is pre-1.0, so a small change can still alter a public contract. Keep each pull request focused. State any effect on CLI behavior, Python APIs, VEX output, or data-sharing boundaries.

## Set up the repository

Install these prerequisites:

- Git.
- GNU Make.
- Python 3.10 or newer.
- The `uv`, `actionlint`, and `shellcheck` versions in `.tool-versions`.

OpenVEX renderer changes also need Go 1.25.8. The version and the `go-vex` 0.2.8 dependency are recorded in `tests/integration/openvex-go/go.mod`. Other Python and documentation work does not require Go locally.

Activate the pinned tools with `mise`, `asdf`, or an equivalent version manager. Then install the locked dependencies:

```bash
uv sync
```

Run the local quality gate before opening a pull request:

```bash
make check
```

CI also checks formatting and enforces 75 percent branch coverage. Run those two policies explicitly:

```bash
uv run --frozen ruff format --check src tests scripts/*.py docs/conf.py
uv run --frozen pytest -m "not live" --cov-fail-under=75
```

Run live compatibility tests only when the test data may be sent to the covered public services:

```bash
make test-live
```

Run the pinned official OpenVEX parser after changing that renderer or its goldens:

```bash
make openvex-interop
```

Build the manual after changing documentation, CLI behavior, package metadata, or a public Python API:

```bash
uv sync --extra docs
make docs
```

## Follow the project conventions

The enforceable Python rules live in [docs/development/python-style.md](docs/development/python-style.md). The vendored Google guide is background material; `pyproject.toml` and the project policy win when they differ.

Package versions come from Git tags through `setuptools-scm`. Do not put a release version in `pyproject.toml` or package source. A build may create `src/vexcalibur/_version.py`; leave that generated file uncommitted.

Use `vMAJOR.MINOR.PATCH` release tags. The automated release and PyPI workflows validate the exact release commit and its built metadata. Maintainers should follow the [PyPI publishing runbook](docs/how-to/publish-to-pypi.md).

## Prepare the pull request

Include:

- the problem and the chosen solution.
- tests for changed behavior.
- the commands you ran.
- compatibility notes for public surface changes.
- security notes when the change affects VEX output, package URLs, provider access, tokens, or CI permissions.

Report vulnerabilities through the private channel in [SECURITY.md](SECURITY.md), not in a pull request or public issue.
