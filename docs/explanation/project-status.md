# Project status and compatibility

Vexcalibur has published releases and supports the workflows in this manual. It has not reached 1.0, so those releases do not yet promise a stable CLI or Python API.

Pin exact package and action versions in automation. Do not use a mutable branch for a production workflow.

## Published in version 0.1.1

- CycloneDX JSON and XML SBOM input for versions 1.4, 1.5, and 1.6
- GitHub Dependency Graph SBOM input through `--github-repo OWNER/REPO`
- public OSV queries with `--allow-public-osv`
- private OSV-compatible endpoints through `--osv-url`
- local findings with `--offline --findings-file`
- CycloneDX 1.6 VEX JSON output
- repeatable serialization when the SBOM, findings, and timestamp are controlled
- a limited `vexy` compatibility executable
- a released companion GitHub Action

The repository runs its Python, package, and documentation gates on every change. Supply-chain checks cover dependencies, secrets, CodeQL, and OpenSSF Scorecard.

## Implemented in the current source tree

The source tree writes OpenVEX 0.2.0 JSON with explicit author metadata. Published version 0.1.1 does not include this output or its CLI flags. OpenVEX will enter the published package in the next release.

OpenVEX goldens pass the pinned official schema and `go-vex` parser.

## Unstable before 1.0

These surfaces may change between releases:

- command names, flags, defaults, messages, and exit behavior.
- Python imports, signatures, types, and exceptions.
- output details outside the documented CycloneDX and OpenVEX contracts.
- provider configuration and extension hooks.
- GitHub token lookup and Enterprise configuration.
- compatibility pairings between the package and its integrations.

Read release notes before upgrading, even across patch releases.

## Not implemented

Vexcalibur does not read VEX documents. It does not convert between VEX formats.

CSAF output is not implemented. Source-tree OpenVEX support is output-only and targets the pinned 0.2.0 contract.

OSV findings do not yet pass through a policy engine that can decide deployment-specific exploitability. They use `in_triage` and require review.

The `vexy` adapter does not support legacy CycloneDX XML VEX output, CycloneDX 1.4 VEX output, or OSS Index credentials and queries.
