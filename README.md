# Vexcalibur

Vexcalibur is an early VEX toolkit for vulnerability exploitability workflows across SBOM, package URL, and vulnerability data ecosystems.

The project is intended to replace legacy `vexy` usage while staying general-purpose instead of becoming Python-specific. The current scaffold includes an OSV-backed package URL query command, a typed OSV API client, a placeholder `vexy` compatibility command, and CI for Python package quality gates.

## Status

Pre-alpha. The public CLI and output formats are not stable yet.

Implemented now:

- Query OSV for one or more package URLs with `vexcalibur query-osv`.
- Generate CycloneDX 1.6 VEX JSON from CycloneDX JSON SBOM input with `vexcalibur generate`.
- Use the same installed package through the legacy `vexy` executable name.
- Run offline tests, live OSV compatibility tests, linting, formatting checks, type checks, build checks, secret scanning, CodeQL, dependency review, and OpenSSF Scorecard.

Not implemented yet:

- CycloneDX XML SBOM input.
- User-authored exploitability analysis details beyond a single selected CycloneDX analysis state.
- Compatibility with existing `vexy` flags and output.
- A stable `vexcalibur-action` release.

## Development

Prerequisites:

- Python 3.10 or newer
- Poetry 2.x

Install dependencies:

```bash
poetry install
```

Run tests:

```bash
poetry run pytest
```

Run only offline tests:

```bash
poetry run pytest -m "not live"
```

Run the live OSV compatibility smoke test:

```bash
poetry run pytest -m live -q
```

Run static checks:

```bash
poetry run ruff check .
poetry run mypy src
```

Try the CLI:

```bash
poetry run vexcalibur --help
```

Query OSV for a package URL:

```bash
poetry run vexcalibur query-osv pkg:pypi/django@1.2
```

Expected result: the command prints the submitted package URL and any OSV vulnerability IDs returned by `https://api.osv.dev`.

Generate CycloneDX VEX JSON from a CycloneDX JSON SBOM:

```bash
poetry run vexcalibur generate sbom.json --output vex.json
```

For reproducible CI output, provide a timestamp:

```bash
poetry run vexcalibur generate sbom.json --timestamp 2026-06-23T00:00:00Z --output vex.json
```

The initial generator queries OSV for components with package URLs, emits one CycloneDX vulnerability entry per OSV vulnerability ID, and marks findings `in_triage` by default. Use `--analysis-state` to select another CycloneDX state for all generated findings.

## Project Links

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
