# Vexcalibur

![Vexcalibur wordmark and sword logo](https://raw.githubusercontent.com/vexcalibur-dev/vexcalibur/400083ecc7061cea5aff63305ae9d06a7dc9c3f5/docs/assets/vexcalibur-banner.png)

[![CI](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/ci.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/ci.yml)
[![CodeQL](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/codeql.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/scorecard.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/scorecard.yml)
[![Dependency Review](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/vexcalibur-dev/vexcalibur/actions/workflows/dependency-review.yml)

Vexcalibur helps security and release engineers generate Vulnerability Exploitability eXchange (VEX) documents from software bills of materials (SBOMs) and vulnerability findings. Use it from the command line, Python, or your CI pipeline.

[Documentation](https://vexcalibur-dev.github.io/vexcalibur/) |
[Quickstart](https://vexcalibur-dev.github.io/vexcalibur/tutorials/quickstart.html) |
[Python API](https://vexcalibur-dev.github.io/vexcalibur/how-to/use-python-api.html) |
[Releases](https://github.com/vexcalibur-dev/vexcalibur/releases)

## Install

Vexcalibur supports Python 3.10 through 3.14. With `uv`:

```bash
uv tool install vexcalibur
vexcalibur --help
```

Or use `pip` in a virtual environment on Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install vexcalibur
vexcalibur --help
```

The help output lists the available commands. See the [installation guide](https://vexcalibur-dev.github.io/vexcalibur/install.html) for Windows setup, PATH troubleshooting, and version pinning. Pin an exact release in automation so upgrades are deliberate.

## Generate a VEX document

With your own SBOM and a [local findings file](https://vexcalibur-dev.github.io/vexcalibur/reference/local-findings.html), replace the input paths below:

```bash
vexcalibur generate sbom.json \
  --offline \
  --findings-file findings.json \
  --output vex.json
```

This writes CycloneDX VEX to `vex.json` without contacting a vulnerability service. For a guided example with sample inputs, follow the [quickstart](https://vexcalibur-dev.github.io/vexcalibur/tutorials/quickstart.html).

Vexcalibur reads CycloneDX, SPDX 2.3, and SPDX 3 SBOM files, or fetches an SBOM from GitHub. It generates CycloneDX, OpenVEX, CSAF, and SPDX 3 VEX documents. The [generation guides](https://vexcalibur-dev.github.io/vexcalibur/#how-to-guides) explain the inputs and metadata each format needs.

Findings can also come from an OSV-compatible service. Public OSV requires explicit `--allow-public-osv` consent, which sends package URLs and versions to `https://api.osv.dev`. Fetching an SBOM from GitHub does not grant that consent. See the [finding-source options](https://vexcalibur-dev.github.io/vexcalibur/how-to/generate-cyclonedx-vex.html) before using a network provider with private inventory.

## Integrations

- [GitHub Action](https://github.com/vexcalibur-dev/vexcalibur-action#readme)
- [CircleCI Orb](https://github.com/vexcalibur-dev/vexcalibur-orb#readme)
- [Python API guide](https://vexcalibur-dev.github.io/vexcalibur/how-to/use-python-api.html) and [reference](https://vexcalibur-dev.github.io/vexcalibur/reference/python-api.html)
- [Vexy migration and supported options](https://vexcalibur-dev.github.io/vexcalibur/reference/cli.html#vexy)

The [compatibility policy](https://vexcalibur-dev.github.io/vexcalibur/reference/compatibility.html) defines the CLI, API, and output contracts. For machine-readable run results, see [execution reports](https://vexcalibur-dev.github.io/vexcalibur/reference/execution-report.html).

## Contributing and support

Read [CONTRIBUTING.md](https://github.com/vexcalibur-dev/vexcalibur/blob/main/CONTRIBUTING.md) for development setup and checks. Use the [issue forms](https://github.com/vexcalibur-dev/vexcalibur/issues) for questions and bug reports; report vulnerabilities through the [security policy](https://github.com/vexcalibur-dev/vexcalibur/security/policy).

Licensed under [Apache License 2.0](https://github.com/vexcalibur-dev/vexcalibur/blob/400083ecc7061cea5aff63305ae9d06a7dc9c3f5/LICENSE).
