# AGENTS.md

This file gives AI agents and automated contributors repo-specific guidance for Vexcalibur.

## Project Overview

Vexcalibur is a usable-but-unstable VEX toolkit for workflows around SBOMs, package URLs, vulnerability sources, and VEX documents. It is intended to replace legacy `vexy` usage over time while remaining a general-purpose VEX tool, not a Python-only vulnerability tool.

The current implementation is Python, but product and domain decisions should stay ecosystem-neutral unless an issue explicitly narrows the scope.

## Non-Negotiables

- Do not send SBOM contents, package URLs, component versions, or project inventories to public services unless the user, command, test, or issue explicitly opts in.
- Public OSV access requires `--allow-public-osv`; use fixtures, fakes, or private mirror URLs for normal tests and examples.
- Offline VEX generation uses `--findings-file` and must not construct or query an OSV client.
- Keep changes focused. Avoid broad refactors unless the active issue requires them.
- Preserve public API and output compatibility notes in PR descriptions when behavior changes.
- Treat documentation as product surface. Keep docs accurate for the current supported workflows and pre-1.0 compatibility limits.
- Do not revert unrelated local changes. Work with them or ask if they block the task.

## Technology Stack

- Language: Python 3.10+
- Packaging: uv with `pyproject.toml` and `uv.lock`
- CLI: Typer
- HTTP: httpx
- Data modeling: Pydantic where structured validation is needed
- SBOM/VEX domain: CycloneDX JSON first, with room for more formats
- CI: GitHub Actions across Python 3.10 through 3.14
- Quality: Ruff, MyPy strict mode, pytest, pytest-cov, pip-audit, detect-secrets

## Common Commands

Install dependencies:

```bash
uv sync
```

Install documentation dependencies:

```bash
uv sync --extra docs
```

Run the usual local gate:

```bash
make check
```

Run individual checks:

```bash
make lint
make typecheck
make test
make docs
make audit
make secrets
make secrets-pr
make build
make pre-commit
```

Run live OSV compatibility only when the change intentionally exercises the public OSV service:

```bash
make test-live
```

If a sandboxed agent cannot write uv or pip cache files under the home directory, use a
`/tmp` uv cache:

```bash
UV_CACHE_DIR=/tmp/vexcalibur-uv-cache \
uv sync
```

Use the same `UV_CACHE_DIR` value on subsequent `uv run --frozen ...` commands in that
session.

## Architecture

Core modules live under `src/vexcalibur/`:

- `cli.py`: Typer commands and user-facing error handling.
- `generate.py`: SBOM-to-VEX workflow orchestration.
- `sbom.py`: SBOM parsing and component identity extraction.
- `vex.py`: CycloneDX VEX rendering and timestamp handling.
- `sources/osv.py`: OSV client, OSV response parsing, source policy checks, and OSV-to-domain mapping.
- `sources/local.py`: Local findings parsing for offline VEX generation.
- `domain.py`: Shared domain objects.
- `compat/vexy.py`: Legacy command entrypoint. Vexy compatibility is intentionally lower priority than core VEX engine work.

Keep source-provider concerns in `sources/`. Workflow modules should orchestrate providers, not duplicate provider policy or parsing details.

## Public Data Policy

Vexcalibur must fail closed for public vulnerability services.

- `query-osv` and `generate` must not query `https://api.osv.dev` unless `--allow-public-osv` is present.
- Private mirrors should use `--osv-url`.
- Tests that verify public OSV behavior should use fakes unless marked `live`.
- Host checks must handle public OSV aliases that resolve through case folding, trailing dots, or IDNA dot normalization.
- Injected source clients should still be checked against their effective base URL when that URL is knowable.

## Code Style

Use the project-owned [Python style policy](docs/development/python-style.md) as the canonical style contract. The vendored [Google Python Style Guide](docs/external/google-python-style-guide.md) is background reference material only; do not treat conflicting upstream rules as enforceable Vexcalibur policy.

## Testing

- Put unit and integration tests under `tests/`.
- Keep external-service tests marked with `@pytest.mark.live`.
- Use deterministic fixtures and golden files for VEX output.
- Add regression tests for security and compatibility fixes.
- For SBOM and VEX changes, test both successful behavior and malformed/unsafe input.
- Maintain the configured coverage floor unless a PR intentionally adjusts the quality policy.

## Documentation

Docs should grow deliberately using Diataxis categories:

- Tutorials for guided first-use workflows.
- How-to guides for task-oriented recipes.
- Reference for CLI, action inputs, schemas, and APIs.
- Explanation for architecture, trust boundaries, source-provider behavior, and VEX semantics.

The README should stay accurate and concise for the current release state. Avoid promising features that are only planned. When docs change, run a documentation-focused review before merge; use the scorched-earth documentation review skill when available.

Sphinx documentation lives under `docs/` and builds with `make docs`. Keep conceptual documentation in Diataxis sections, but keep API details close to code through docstrings and `docs/reference/python-api.rst` autodoc pages.

## Versioning And Publishing

Never commit a real package version number. `pyproject.toml` uses
`dynamic = ["version"]`, and `setuptools-scm` derives package versions from Git
tags.

- Release tags use `vMAJOR.MINOR.PATCH`, for example `v0.1.0`.
- The first PyPI release should be tag `v0.1.0`.
- Do not replace `dynamic = ["version"]` with a committed `[project].version`.
- `setuptools-scm` may generate `src/vexcalibur/_version.py` while building
  distributions. It is ignored and must not be committed.
- Publishing uses `.github/workflows/pypi.yml` and the `pypi` GitHub
  environment for PyPI trusted publishing. Publish by creating a GitHub Release
  for a matching tag on `main`; do not add manual publishing paths without a
  security review.
- Follow `docs/how-to/publish-to-pypi.md` for release preflight, publishing,
  verification, and mitigation steps.
- Release builds must fetch tags with full Git history before building
  distributions.

## PR Expectations

Use conventional commit style for branch commits and PR titles. PRs should be ready for review unless the user explicitly asks for a draft.

Before merging meaningful changes, run or confirm:

```bash
uv lock --check
uv sync --frozen
uv run --frozen ruff format --check src tests docs/conf.py
uv run --frozen ruff check src tests docs/conf.py
uv run --frozen mypy src
uv run --frozen pytest -m "not live" --cov-fail-under=75
make docs
uv build --clear --no-create-gitignore --no-sources
uv run --frozen pip-audit --cache-dir /tmp/vexcalibur-pip-audit-cache
git ls-files -z | xargs -0 uv run --frozen detect-secrets-hook --baseline .secrets.baseline --
git show origin/main:.secrets.baseline > /tmp/vexcalibur-base.secrets.baseline
git ls-files -z | xargs -0 uv run --frozen detect-secrets-hook --baseline /tmp/vexcalibur-base.secrets.baseline --
```

Use `make secrets` for current-branch baseline enforcement, `make secrets-pr` for PR-mode
base-baseline enforcement, and `make secrets-baseline` only for an intentional, separately
reviewed baseline refresh.

Run `uv run --frozen pytest -m live -q` only when the change intentionally validates public OSV compatibility.

For new PRs, run separate review passes for security, code correctness, QA, and code quality when subagent review is available. Run thermonuclear code review for substantive code changes and scorched-earth documentation review for substantive documentation changes.
