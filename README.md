# Vexcalibur

![Vexcalibur wordmark and sword logo](https://raw.githubusercontent.com/vexcalibur-dev/vexcalibur/400083ecc7061cea5aff63305ae9d06a7dc9c3f5/docs/assets/vexcalibur-banner.png)

[![CI](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/ci.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/ci.yml)
[![CodeQL](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/codeql.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/scorecard.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/scorecard.yml)
[![Dependency Review](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/dependency-review.yml)

Vexcalibur turns software bills of materials and vulnerability findings into VEX documents. It reads CycloneDX SBOMs or a GitHub Dependency Graph SBOM. Findings come from an OSV-compatible service or a local file.

Current releases write CycloneDX 1.6, OpenVEX 0.2.0, and CSAF 2.0 JSON. CSAF
output uses the `csaf_vex` profile.

The project is usable, but still pre-1.0. Pin an exact release because command flags, Python APIs, and detailed output may change.

## What works today

| Area | Support |
| --- | --- |
| SBOM input | CycloneDX JSON and XML 1.4–1.6; GitHub Dependency Graph SPDX 2.3 JSON |
| Finding sources | Public OSV with explicit consent; private OSV-compatible endpoints; local findings files |
| VEX output | CycloneDX 1.6 JSON; OpenVEX 0.2.0 JSON; CSAF 2.0 JSON with the `csaf_vex` profile |
| Automation | A companion [GitHub Action](https://github.com/vexcalibur-dev/vexcalibur-action) |
| Migration | A narrow `vexy` command-line compatibility layer |
| Python | 3.10–3.14 |

## Install a release

Open the [release page](https://github.com/vexcalibur-dev/vexcalibur/releases)
and choose an exact version. The commands prompt for that version so an
unresolved placeholder cannot reach `pip`:

```bash
set -euo pipefail

read -r -p "Vexcalibur version from the release page: " VEXCALIBUR_VERSION
if [[ ! "$VEXCALIBUR_VERSION" =~ ^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
  printf 'Enter a MAJOR.MINOR.PATCH release version\n' >&2
  exit 2
fi
VEXCALIBUR_VENV=".venv-vexcalibur-${VEXCALIBUR_VERSION}"
if [[ -e "$VEXCALIBUR_VENV" ]]; then
  printf 'Refusing to reuse %s\n' "$VEXCALIBUR_VENV" >&2
  exit 2
fi
python -m venv "$VEXCALIBUR_VENV"
"$VEXCALIBUR_VENV/bin/python" -m pip install \
  "vexcalibur==${VEXCALIBUR_VERSION}"
INSTALLED_VERSION="$("$VEXCALIBUR_VENV/bin/python" -c \
  'from importlib.metadata import version; print(version("vexcalibur"))')"
test "$INSTALLED_VERSION" = "$VEXCALIBUR_VERSION"
"$VEXCALIBUR_VENV/bin/vexcalibur" --help
```

In PowerShell 7.3 or newer, use:

```powershell
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
$VEXCALIBUR_VERSION = Read-Host "Vexcalibur version from the release page"
if ($VEXCALIBUR_VERSION -notmatch '^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$') {
    throw "Enter a MAJOR.MINOR.PATCH release version"
}
$VEXCALIBUR_VENV = ".venv-vexcalibur-$VEXCALIBUR_VERSION"
if (Test-Path -LiteralPath $VEXCALIBUR_VENV) {
    throw "Refusing to reuse $VEXCALIBUR_VENV"
}
py -m venv $VEXCALIBUR_VENV
$PYTHON = Join-Path $VEXCALIBUR_VENV "Scripts/python.exe"
$VEXCALIBUR = Join-Path $VEXCALIBUR_VENV "Scripts/vexcalibur.exe"
& $PYTHON -m pip install "vexcalibur==$VEXCALIBUR_VERSION"
$INSTALLED_VERSION = & $PYTHON -c `
    'from importlib.metadata import version; print(version("vexcalibur"))'
if ($INSTALLED_VERSION -ne $VEXCALIBUR_VERSION) {
    throw "Installed $INSTALLED_VERSION instead of $VEXCALIBUR_VERSION"
}
& $VEXCALIBUR --help
```

## Try local generation

Clone the repository, then install its locked dependencies:

```bash
uv sync
```

Dependency installation may contact the configured package index. The generation command below uses only local inputs and does not contact a vulnerability service.

Generate a VEX document from the committed example files:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

Check the result:

```bash
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-vex.json").read_text())
assert vex["bomFormat"] == "CycloneDX"
assert vex["specVersion"] == "1.6"
assert len(vex["vulnerabilities"]) == 5
print("generated CycloneDX VEX")
PY
```

See the [quickstart](https://vexcalibur-dev.github.io/vexcalibur/tutorials/quickstart.html) for the guided version of this example.

CycloneDX remains the default output. Add `--format openvex` and identify the
document author to create OpenVEX. Add `--format csaf` and the required
document and publisher metadata to create a CSAF 2.0 VEX document. Follow the [OpenVEX
guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-openvex.html)
or [CSAF
guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-csaf.html)
for a runnable example and the format's evidence rules.

## Choose a finding source

Vexcalibur requires one finding source for each generation run.

| Inventory and trust boundary | Use |
| --- | --- |
| Findings already exist locally | Use `--findings-file findings.json`. Add `--offline` for a local SBOM. |
| Inventory may go to an internal service | `--osv-url https://osv.internal.example` |
| Inventory is approved for public OSV | `--allow-public-osv` |

> **Warning:** `--allow-public-osv` sends package URLs and versions to `https://api.osv.dev`. Do not use it with a private SBOM or sensitive package inventory unless that disclosure is approved.

The default public endpoint fails closed without that flag. Fetching an SBOM from GitHub is a separate network boundary and does not grant permission to send the resulting inventory to public OSV.

## Documentation

- Start with the [quickstart](https://vexcalibur-dev.github.io/vexcalibur/tutorials/quickstart.html).
- Follow the [CycloneDX](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-cyclonedx-vex.html), [OpenVEX](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-openvex.html), or [CSAF](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-csaf.html) generation guide.
- Use the [CLI reference](https://vexcalibur-dev.github.io/vexcalibur/reference/cli.html) for flags and failure behavior.
- The default-branch [execution report reference](https://vexcalibur-dev.github.io/vexcalibur/reference/execution-report.html) covers machine-readable generation metadata. Before using it, verify that the selected release lists `--execution-report` in `vexcalibur generate --help`.
- The CLI report transaction supports Linux and macOS. Windows embeddings can construct and validate the same report through the Python API.
- Read the [CycloneDX](https://vexcalibur-dev.github.io/vexcalibur/reference/cyclonedx-vex-output.html), [OpenVEX](https://vexcalibur-dev.github.io/vexcalibur/reference/openvex-output.html), or [CSAF](https://vexcalibur-dev.github.io/vexcalibur/reference/csaf-output.html) output contract before consuming generated files.
- Read the [architecture](https://vexcalibur-dev.github.io/vexcalibur/explanation/architecture.html) before adding a source or output format.
- Read the [self-release evidence design](https://vexcalibur-dev.github.io/vexcalibur/explanation/self-release-evidence.html), inspect a [local bundle](https://vexcalibur-dev.github.io/vexcalibur/how-to/build-release-evidence.html), or follow the [immutable release runbook](https://vexcalibur-dev.github.io/vexcalibur/how-to/publish-to-pypi.html).
- Check [project status](https://vexcalibur-dev.github.io/vexcalibur/explanation/project-status.html) for current limits.

The complete manual is at [vexcalibur-dev.github.io/vexcalibur][vexcalibur-docs].

## Contributing

Run the local quality gate:

```bash
make check
```

Documentation changes must also build without warnings:

```bash
uv sync --extra docs
make docs
```

Parser, source-client, package-URL, and terminal-safety changes must also run
the deterministic fuzz smoke profile:

```bash
make fuzz-smoke
```

See the [contribution guide](https://github.com/vexcalibur-dev/vexcalibur/blob/main/CONTRIBUTING.md),
the [security policy](https://github.com/vexcalibur-dev/vexcalibur/security/policy), the
[fuzzing guide](https://vexcalibur-dev.github.io/vexcalibur/development/fuzzing.html),
and the [Python style policy](https://vexcalibur-dev.github.io/vexcalibur/development/python-style.html)
before opening a pull request.

Use the [issue forms](https://github.com/vexcalibur-dev/vexcalibur/issues) for questions, bugs, and feature requests. The organization [support policy](https://github.com/vexcalibur-dev/.github/blob/main/SUPPORT.md) explains which public route to use, and the [code of conduct](https://github.com/vexcalibur-dev/.github/blob/main/CODE_OF_CONDUCT.md) applies to project spaces.

Vexcalibur is licensed under the [Apache License 2.0](https://github.com/vexcalibur-dev/vexcalibur/blob/400083ecc7061cea5aff63305ae9d06a7dc9c3f5/LICENSE).

[vexcalibur-docs]: https://vexcalibur-dev.github.io/vexcalibur/
