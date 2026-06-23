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
- User-authored exploitability analysis details and policy-driven VEX states.
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
poetry run vexcalibur generate tests/fixtures/sbom/cyclonedx-json-simple.json --output /tmp/vexcalibur-vex.json
```

For reproducible CI output, provide a timestamp:

```bash
poetry run vexcalibur generate tests/fixtures/sbom/cyclonedx-json-simple.json --timestamp 2026-06-23T00:00:00Z --output /tmp/vexcalibur-vex.json
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-vex.json").read_text())
assert vex["bomFormat"] == "CycloneDX"
assert vex["specVersion"] == "1.6"
assert vex["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
print(f"validated {len(vex['vulnerabilities'])} generated VEX findings")
PY
```

The initial generator queries OSV for versioned components with package URLs, emits CycloneDX vulnerability entries for OSV matches, and marks findings `in_triage` by default.

By default, `generate` sends package URL inventory from the SBOM to the public OSV API at `https://api.osv.dev`. Do not use it with private SBOMs or sensitive package inventories until Vexcalibur has an offline or private OSV mirror mode.

## Project Links

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)
