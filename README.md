# Vexcalibur

![Vexcalibur wordmark and sword logo](https://raw.githubusercontent.com/vexcalibur-dev/vexcalibur/400083ecc7061cea5aff63305ae9d06a7dc9c3f5/docs/assets/vexcalibur-banner.png)

[![CI](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/ci.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/ci.yml)
[![CodeQL](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/codeql.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/scorecard.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/scorecard.yml)
[![Dependency Review](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/dependency-review.yml)

Vexcalibur turns software bills of materials and vulnerability findings into VEX documents, for the security and release engineers who publish VEX statements alongside an SBOM. It reads CycloneDX SBOMs or a GitHub Dependency Graph SBOM. Findings come from an OSV-compatible service or a local file.

Current releases write CycloneDX 1.6, OpenVEX 0.2.0, CSAF 2.0, and SPDX 3.0.1
JSON. CSAF output uses the `csaf_vex` profile, and SPDX 3 output goes through
the security profile's VEX relationships. SPDX 3 arrived in `v0.7.0`.

The project is usable, but still pre-1.0. Pin an exact release because command flags, Python APIs, and detailed output may change.

## What works today

| Area | Support |
| --- | --- |
| SBOM input | CycloneDX JSON and XML 1.4–1.6; GitHub Dependency Graph SPDX 2.3 JSON |
| Finding sources | Public OSV with explicit consent; private OSV-compatible endpoints; local findings files |
| VEX output | CycloneDX 1.6 JSON; OpenVEX 0.2.0 JSON; CSAF 2.0 JSON with the `csaf_vex` profile; SPDX 3.0.1 JSON-LD with the security profile |
| Automation | A companion [GitHub Action](https://github.com/vexcalibur-dev/vexcalibur-action) |
| Migration | A narrow `vexy` command-line compatibility layer |
| Python | 3.10–3.14 |

## Install a release

Vexcalibur needs Python 3.10 through 3.14.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install vexcalibur
vexcalibur --help
```

In PowerShell, the virtual environment puts its commands under `Scripts`:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install vexcalibur
vexcalibur --help
```

With `uv`, one command handles the environment and there's nothing to activate:

```bash
uv tool install vexcalibur
```

That gives you the latest release, which is what you want to try it out.
Vexcalibur is pre-1.0, so pin an exact version in anything you automate. The
[install guide](https://vexcalibur-dev.github.io/vexcalibur/install.html)
covers pinning, PATH setup, and how to check which formats your release
supports.

Once it's installed, [generate your first document](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-cyclonedx-vex.html)
against your own SBOM.

## Try local generation from a checkout

Use this path to work on Vexcalibur itself, or to run unreleased output
formats. Clone the repository, then install its locked dependencies:

```bash
uv sync --frozen
```

Installing the dependencies may reach the configured package index. The generate command below uses only local inputs, so it never reaches a vulnerability service.

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
uv run --frozen python - <<'PY'
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

CycloneDX is the default. To write OpenVEX, add `--format openvex` and name the
document author. To write CSAF 2.0, add `--format csaf` and the document and
publisher metadata it needs. The [OpenVEX
guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-openvex.html)
and [CSAF
guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-csaf.html)
each carry a runnable example and the evidence rules for that format.

## Choose a finding source

Vexcalibur needs exactly one finding source per run.

| Inventory and trust boundary | Use |
| --- | --- |
| Findings already exist locally | Use `--findings-file findings.json`. Add `--offline` for a local SBOM. |
| Inventory may go to an internal service | `--osv-url https://osv.internal.example` |
| Inventory is approved for public OSV | `--allow-public-osv` |

> **Warning:** `--allow-public-osv` sends package URLs and versions to `https://api.osv.dev`. Do not use it with a private SBOM or sensitive package inventory unless that disclosure is approved.

Without that flag, the public endpoint fails closed. Fetching an SBOM from GitHub crosses a separate network boundary; it doesn't give Vexcalibur permission to send the resulting inventory to public OSV.

## Documentation

The complete manual is at [vexcalibur-dev.github.io/vexcalibur][vexcalibur-docs].

### Getting started

Work through the
[quickstart](https://vexcalibur-dev.github.io/vexcalibur/tutorials/quickstart.html),
then follow the
[CycloneDX](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-cyclonedx-vex.html),
[OpenVEX](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-openvex.html),
[CSAF](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-csaf.html), or
[SPDX 3](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-spdx3.html)
generation guide. Check [project
status](https://vexcalibur-dev.github.io/vexcalibur/explanation/project-status.html)
for current limits.

### Running it

The [CLI
reference](https://vexcalibur-dev.github.io/vexcalibur/reference/cli.html)
covers flags and failure behavior. Read the
[CycloneDX](https://vexcalibur-dev.github.io/vexcalibur/reference/cyclonedx-vex-output.html),
[OpenVEX](https://vexcalibur-dev.github.io/vexcalibur/reference/openvex-output.html),
[CSAF](https://vexcalibur-dev.github.io/vexcalibur/reference/csaf-output.html), or
[SPDX 3](https://vexcalibur-dev.github.io/vexcalibur/reference/spdx3-output.html)
output contract before consuming generated files.

### Embedding it

The [Python API
guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/use-python-api.html)
and [API
reference](https://vexcalibur-dev.github.io/vexcalibur/reference/python-api.html)
cover the supported facade. Read the [provider
contract](https://vexcalibur-dev.github.io/vexcalibur/reference/provider-contract.html)
and [renderer
contract](https://vexcalibur-dev.github.io/vexcalibur/reference/renderer-contract.html)
before adding an integration, and the
[architecture](https://vexcalibur-dev.github.io/vexcalibur/explanation/architecture.html)
before adding a source or output format.

### Execution reports

The [execution report
reference](https://vexcalibur-dev.github.io/vexcalibur/reference/execution-report.html)
covers the machine-readable generation metadata, and the [Python report
guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-execution-report-from-python.html)
covers the cross-platform API. Both describe the default branch, so verify that
your release lists `--execution-report` in `vexcalibur generate --help` first.
The CLI report transaction supports Linux and macOS; Windows embeddings build
and validate the same report through the Python facade.

## Contributing

The complete local gate runs on Linux and needs the host tools listed in
[Reproduce important gates](https://vexcalibur-dev.github.io/vexcalibur/contributing/ci.html#reproduce-important-gates).
That guide includes exact portable commands for macOS and Windows. Required
pull-request CI runs the Linux-only checks.

On Linux, run the quality gate:

```bash
make check
```

Documentation changes must also build without warnings:

```bash
uv sync --frozen --extra docs
make docs
```

Parser, source-client, package-URL, and terminal-safety changes must also run
the deterministic fuzz smoke profile:

```bash
make fuzz-smoke
```

See the [contribution guide](https://github.com/vexcalibur-dev/vexcalibur/blob/main/CONTRIBUTING.md)
and the [security policy](https://github.com/vexcalibur-dev/vexcalibur/security/policy)
before opening a pull request. The [contributor
documentation](https://vexcalibur-dev.github.io/vexcalibur/contributing/index.html)
collects the style policy, fuzzing guide, CI layout, and governance checks.

Use the [issue forms](https://github.com/vexcalibur-dev/vexcalibur/issues) for questions, bugs, and feature requests. The organization [support policy](https://github.com/vexcalibur-dev/.github/blob/main/SUPPORT.md) explains which public route to use, and the [code of conduct](https://github.com/vexcalibur-dev/.github/blob/main/CODE_OF_CONDUCT.md) applies to project spaces.

Vexcalibur is licensed under the [Apache License 2.0](https://github.com/vexcalibur-dev/vexcalibur/blob/400083ecc7061cea5aff63305ae9d06a7dc9c3f5/LICENSE).

[vexcalibur-docs]: https://vexcalibur-dev.github.io/vexcalibur/
