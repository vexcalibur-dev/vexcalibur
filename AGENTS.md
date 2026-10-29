# Vexcalibur agent guidance

This file gives automated contributors the repository rules needed to work safely.

## Project state

Vexcalibur is an ecosystem-neutral VEX toolkit. It reads CycloneDX JSON/XML, SPDX 2.3 JSON, and SPDX 3 JSON-LD files,
or a GitHub Dependency Graph SBOM. Findings come from OSV-compatible services
or local JSON. It renders CycloneDX 1.6, OpenVEX 0.2.0, CSAF 2.0, or SPDX
3.0.1 JSON.

The implementation is Python. See the [internal requirements](docs/architecture/quality-attributes.md) for product and behavior constraints.

## Non-negotiable rules

- Preserve unrelated user changes and keep each change within the active task.
- Read the [internal requirements](docs/architecture/quality-attributes.md) before behavior or release work.

## Toolchain

- Python 3.10–3.14
- `uv` with `pyproject.toml` and `uv.lock`
- Typer, HTTPX, Pydantic, and `cyclonedx-python-lib`
- Ruff, strict MyPy, Pytest, `actionlint`, `shellcheck`, `pip-audit`, and `detect-secrets`
- Sphinx and MyST for the manual
- Go 1.25.8 for the pinned OpenVEX interoperability check
- Node 24 and npm for pinned CSAF schema and mandatory-test conformance

`.tool-versions` pins uv, Node, `actionlint`, and `shellcheck`. The supported
Python range is recorded in `pyproject.toml` and exercised by CI. The OpenVEX
interoperability module records Go 1.25.8 and pins `go-vex` 0.2.8 in
`tests/integration/openvex-go/go.mod`. CSAF conformance dependencies and their
lockfile live in `tests/integration/csaf-validator/`.

## Common commands

Install dependencies:

```bash
uv sync --frozen
```

Run the local gate:

```bash
make check
```

Useful focused targets are `make lint`, `make workflow-lint`, `make typecheck`,
`make test`, `make coverage`, `make docs`, `make audit`, `make secrets`,
`make secrets-pr`, `make build`, `make openvex-interop`,
`make csaf-validator-install`, `make csaf-interop`, `make installed-cli-check`,
`make installed-csaf-check`, `make governance-check`, and `make pre-commit`.

`make workflow-lint` needs `actionlint` and `shellcheck` on `PATH`.

Run public-service tests only when the fixture data may leave the runner:

```bash
make test-live
```

If the home cache is read-only, use one cache path for setup and later commands:

```bash
UV_CACHE_DIR=/tmp/vexcalibur-uv-cache uv sync --frozen
UV_CACHE_DIR=/tmp/vexcalibur-uv-cache uv run --frozen pytest -m "not live"
```

## Code boundaries

See the [module map](docs/architecture/overview.md#module-map) for module
responsibilities and [source and rendering boundaries](docs/architecture/quality-attributes.md#source-and-rendering-boundaries)
for the rules governing them.

## Style and tests

Follow [docs/contributing/python-style.md](docs/contributing/python-style.md) and `pyproject.toml`. The vendored Google Python guide is reference material, not the local contract.

Put tests under `tests/`. Mark external calls with `@pytest.mark.live`. Prefer deterministic fixtures and golden output.

Add regression coverage for a parser, security, or compatibility fix. At an untrusted-data boundary, test malformed and unsafe input as well as success.

OpenVEX changes must pass `make openvex-interop`. The nested Go module pins the official implementation used by that check.

CSAF changes must pass `make csaf-interop` and `make installed-csaf-check`
after `make csaf-validator-install`. Keep the official OASIS schema check, the
complete pinned mandatory suite, and the separate filename tests. The Node
validator is a CI/development dependency, not a Python runtime dependency.

## Documentation

Keep the README a concise front door. User docs follow Diataxis: tutorials,
how-to guides, reference, and explanation. Internal architecture and requirements
live in `docs/architecture/`; follow the planning guide for their lifecycle.

Verify commands against the current CLI and build Sphinx with warnings treated as errors:

```bash
uv sync --frozen --extra docs
make docs
```

Match the command runner to the reader. In a source checkout — tutorials and contributor how-tos — run every command through `uv sync --frozen` and `uv run --frozen`, including the interpreter for verification snippets (`uv run --frozen python - <<'PY'`). The interpreter uv provisions lives in the project environment, not on the reader's PATH, so a bare `python` or `python3` there can be absent or the wrong environment even after `uv sync` succeeds. For an installed release — the README install path, or any step that runs `vexcalibur` directly — use plain `vexcalibur` and plain `python`/`python3`, and never require a consumer to install uv. Release-integrity and clean-room checks are the deliberate exception: they may use an isolated `python3 -I` or a fresh `python -m venv` so a misconfigured project environment cannot influence the result or mask a bad published artifact.

For a substantial documentation change, use the scorched-earth documentation review and Green Thumb prose pass when those skills are available.

## Design documents

Read `.trellis.yaml`, [the planning guide](docs/planning/README.md), and the
[internal requirements](docs/architecture/quality-attributes.md) before
changing behavior. Load the architecture sections and contracts relevant to the
task. GitHub issues track execution; don't copy their task lists into a second
roadmap.

## Versions and releases

Read the [version and release requirements](docs/architecture/quality-attributes.md#version-and-release-integrity) and follow the [release procedure](docs/contributing/publish-to-pypi.md). For GitHub settings, follow the [governance requirements](docs/architecture/quality-attributes.md#governance-checks).

## Pull requests

Use a conventional commit style for branch commits and pull request titles. Open pull requests ready for review unless the user asks for a draft.

Before merging a meaningful change, run or confirm:

```bash
uv lock --check
uv sync --frozen --extra docs
uv run --frozen ruff format --check src tests scripts/*.py docs/conf.py docs/examples/*.py
uv run --frozen ruff check src tests scripts/*.py docs/conf.py docs/examples/*.py
uv run --frozen mypy src
make workflow-lint
make installed-cli-check
make openvex-interop
make csaf-validator-install
make csaf-interop
make installed-csaf-check
make coverage COVERAGE_COMPARE_REF=origin/main
make fuzz-smoke
make docs
uv build --clear --no-create-gitignore --no-sources
uv run --frozen pip-audit --cache-dir /tmp/vexcalibur-pip-audit-cache
make secrets
make secrets-pr
```

Use `make secrets-baseline` only for a separate, reviewed baseline update. Run live tests only when the change and test data are approved for public-service access.
