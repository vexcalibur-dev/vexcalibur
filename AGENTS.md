# Vexcalibur agent guidance

This file gives automated contributors the repository rules needed to work safely.

## Project state

Vexcalibur is a pre-1.0 VEX toolkit. It reads CycloneDX files or a GitHub
Dependency Graph SBOM. Findings come from OSV-compatible services or local
JSON. It renders CycloneDX 1.6, OpenVEX 0.2.0, CSAF 2.0, or SPDX 3.0.1 JSON.

The implementation is Python, but domain and product decisions should remain ecosystem-neutral unless an issue narrows the scope. Do not present a planned input, provider, or output format as available.

## Non-negotiable rules

- Never send SBOM content, package URLs, versions, or project inventory to a public service without explicit consent.
- Require `--allow-public-osv` for public OSV. Use fixtures, fakes, private mirrors, or local findings for normal tests and examples.
- Do not construct or query an OSV client in local-findings mode.
- Preserve unrelated user changes and keep each change within the active task.
- Document changes to a CLI, Python API, output contract, provider, or trust boundary.
- Treat documentation as a tested product surface.

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
`make test`, `make docs`, `make audit`, `make secrets`, `make secrets-pr`,
`make build`, `make openvex-interop`, `make csaf-validator-install`,
`make csaf-interop`, `make installed-cli-check`, `make installed-csaf-check`,
`make governance-check`, and `make pre-commit`.

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

Core modules live under `src/vexcalibur/`:

| Module | Responsibility |
| --- | --- |
| `cli.py` | Typer commands and user-facing errors |
| `generate.py` | Workflow orchestration |
| `generate_command.py` | Validated CLI generation requests |
| `generation_result.py` | Immutable generation results and report models |
| `generation_output.py` | VEX and report publication transactions |
| `execution_report_destination.py` | Descriptor-bound POSIX file writes |
| `sbom.py` | Local CycloneDX parsing and component extraction |
| `github_sbom.py` | GitHub Dependency Graph SBOM access and SPDX extraction |
| `domain.py` | Provider-neutral components, findings, and source protocol |
| `document.py` | Immutable format-neutral document, product, and assertion values |
| `sources/osv.py` | OSV policy, client, parsing, and domain mapping |
| `sources/local.py` | Local findings validation and matching |
| `render.py` | Format-neutral renderer protocol and output selector |
| `vex.py` | CycloneDX 1.6 rendering |
| `openvex.py` | Native OpenVEX 0.2.0 rendering |
| `csaf.py` | Native CSAF 2.0 VEX rendering and document metadata |
| `compat/vexy.py` | Limited legacy command adapter |

Keep provider code in `sources/`. A provider returns domain findings and does not render a VEX format. A renderer consumes domain values and does not query a source.

Keep format-specific mapping inside its renderer. Do not silently treat source update times as statement revision times or analysis prose as remediation guidance.

`vexcalibur.api` is the supported Python facade. Public examples and external
consumer tests must import through it. Other modules are implementation details
unless that facade re-exports a name.

## Public data policy

Public vulnerability services fail closed.

- `query-osv` and `generate` require `--allow-public-osv` for `https://api.osv.dev`.
- Private OSV-compatible services use `--osv-url`.
- Tests use fake clients unless marked `live`.
- Host checks account for case, trailing dots, and IDNA dot normalization.
- An injected client remains subject to public-endpoint checks when its URL is knowable.
- Fetching a GitHub SBOM does not grant consent for a later public OSV query.

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

Keep the README a concise front door. Put guided learning in tutorials, task recipes in how-to guides, contracts in reference, and design context in explanation.

Do not promise planned behavior. Verify commands against the current CLI and build Sphinx with warnings treated as errors:

```bash
uv sync --frozen --extra docs
make docs
```

Match the command runner to the reader. In a source checkout — tutorials and contributor how-tos — run every command through `uv sync --frozen` and `uv run --frozen`, including the interpreter for verification snippets (`uv run --frozen python - <<'PY'`). The interpreter uv provisions lives in the project environment, not on the reader's PATH, so a bare `python` or `python3` there can be absent or the wrong environment even after `uv sync` succeeds. For an installed release — the README install path, or any step that runs `vexcalibur` directly — use plain `vexcalibur` and plain `python`/`python3`, and never require a consumer to install uv. Release-integrity and clean-room checks are the deliberate exception: they may use an isolated `python3 -I` or a fresh `python -m venv` so a misconfigured project environment cannot influence the result or mask a bad published artifact.

For a substantial documentation change, use the scorched-earth documentation review and Green Thumb prose pass when those skills are available.

## Versions and releases

`setuptools-scm` derives versions from `vMAJOR.MINOR.PATCH` tags. Do not add a literal project version or commit generated `src/vexcalibur/_version.py`.

The tag is the release. Nothing commits to the repository after the release
version is calculated: no version bump, no changelog write-back, no
substituting the tag into tracked files. A process that commits after tagging
leaves the tagged commit holding something other than the released bytes, which
breaks the evidence tying a release to what shipped. Anything needing the
version derives it at build time from the tag.

That covers documentation, not only code. Don't write the current release
version into prose, install commands, or examples, because no release step
updates it afterward. Install commands install unpinned. Where a guide has to
show how to pin, use a permanently true version such as the first release and
say it is there for the form. Where a reader needs the current version, give
them a command that computes it rather than a number to copy. Historical
references are fine — which release first shipped a format, or a minimum
supported version — because they stay true.

Versions owned by another repository don't belong here either. The GitHub
Action depends on Vexcalibur rather than the reverse, so its commit pins,
inputs, and compatibility declarations are documented in
`vexcalibur-dev/vexcalibur-action`.

`.github/workflows/release.yml` derives a version from Conventional Commits and validates the exact `main` commit. The `vexcalibur-dev-automation` GitHub App creates the tag and GitHub Release.

`.github/workflows/pypi.yml` accepts only an automation-authored immutable
release whose exact tagged commit remains an ancestor of current `main`. It
publishes through Trusted Publishing.

Follow [docs/contributing/publish-to-pypi.md](docs/contributing/publish-to-pypi.md) for release work. Do not add a manual upload path without a security review.

GitHub organization, repository, environment, and security settings are covered
by the read-only policy in
[docs/contributing/github-governance.md](docs/contributing/github-governance.md).
Run `make governance-check` after changing those settings. The command must fail
if any required endpoint is inaccessible; do not add a stored administrator
token to CI to make it periodic.

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
uv run --frozen pytest -m "not live" --cov-fail-under=75
make docs
uv build --clear --no-create-gitignore --no-sources
uv run --frozen pip-audit --cache-dir /tmp/vexcalibur-pip-audit-cache
make secrets
make secrets-pr
```

Use `make secrets-baseline` only for a separate, reviewed baseline update. Run live tests only when the change and test data are approved for public-service access.
