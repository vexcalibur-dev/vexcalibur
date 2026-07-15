# Vexcalibur

Vexcalibur turns SBOM package inventories and vulnerability findings into VEX
documents. Version 0.3.1 reads CycloneDX files or a GitHub Dependency Graph
SBOM. It collects findings from OSV-compatible services or local JSON. It
writes CycloneDX 1.6, OpenVEX 0.2.0, or CSAF 2.0 JSON.

Public OSV access fails closed. Vexcalibur sends package URLs and versions to `https://api.osv.dev` only when a command includes `--allow-public-osv`.

Vexcalibur is pre-1.0. Pin an exact release and review the [project status](explanation/project-status.md) before depending on a public contract.

## Tutorials

- [Generate your first VEX document](tutorials/quickstart.md)
- [Write and use a local findings file](tutorials/offline-local-findings.md)

## How-to guides

- [Generate CycloneDX VEX](how-to/generate-cyclonedx-vex.md)
- [Generate OpenVEX](how-to/generate-openvex.md)
- [Generate CSAF VEX](how-to/generate-csaf.md)
- [Use a private OSV mirror](how-to/use-private-osv-mirror.md)
- [Build and review self-release evidence](how-to/build-release-evidence.md)
- [Publish Vexcalibur to PyPI](how-to/publish-to-pypi.md)

## Reference

- [Command-line interface](reference/cli.md)
- [CycloneDX VEX output](reference/cyclonedx-vex-output.md)
- [OpenVEX output](reference/openvex-output.md)
- [CSAF output](reference/csaf-output.md)
- [Local findings format](reference/local-findings.md)
- [Release-evidence bundle](reference/release-evidence.md)
- [Vulnerability-source provider contract](reference/provider-contract.md)
- [Python API](reference/python-api.rst)

## Explanation

- [Architecture and trust boundaries](explanation/architecture.md)
- [Project status and compatibility](explanation/project-status.md)
- [Why Vexcalibur builds its own release evidence](explanation/self-release-evidence.md)

## Contributor documentation

- [CI, releases, and recurring checks](development/ci.md)
- [Fuzz untrusted input boundaries](development/fuzzing.md)
- [Verify GitHub governance](development/github-governance.md)
- [Python style policy](development/python-style.md)
- [Vendored external documents](external/README.md)

```{toctree}
:hidden:
:maxdepth: 2

tutorials/quickstart
tutorials/offline-local-findings
how-to/generate-cyclonedx-vex
how-to/generate-openvex
how-to/generate-csaf
how-to/use-private-osv-mirror
how-to/build-release-evidence
how-to/publish-to-pypi
reference/cli
reference/cyclonedx-vex-output
reference/openvex-output
reference/csaf-output
reference/provider-contract
reference/python-api
reference/local-findings
reference/release-evidence
explanation/architecture
explanation/project-status
explanation/self-release-evidence
development/ci
development/fuzzing
development/github-governance
development/python-style
external/README
```
