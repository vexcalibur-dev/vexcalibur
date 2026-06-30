# Vexcalibur Documentation

Vexcalibur is a general-purpose toolkit for producing and transforming Vulnerability Exploitability eXchange documents from SBOMs and vulnerability data sources.

The current implementation supports CycloneDX JSON and XML SBOM ingest, OSV-compatible finding discovery, local no-network findings, and CycloneDX 1.6 VEX JSON output. Public OSV access is fail-closed: commands must opt in with `--allow-public-osv` before package URLs, versions, or SBOM-derived inventories are sent to `https://api.osv.dev`.

Vexcalibur is usable for those workflows today, but public contracts remain unstable before 1.0. CLI flags, Python APIs, and output details can change until the project publishes a stable compatibility policy.

## Start Here

- [Quickstart tutorial](tutorials/quickstart.md) walks through generating a VEX document from the repository's public fixture SBOM.
- [No-network local findings tutorial](tutorials/offline-local-findings.md) walks through generating VEX without contacting a public service.
- [Generate CycloneDX VEX](how-to/generate-cyclonedx-vex.md) covers task-oriented generation commands and source configuration.
- [Use a private OSV mirror](how-to/use-private-osv-mirror.md) shows how to keep private SBOM inventories away from public OSV.
- [CLI reference](reference/cli.md) lists the current command surface.
- [CycloneDX VEX output reference](reference/cyclonedx-vex-output.md) describes generated document shape and determinism.
- [Provider contract reference](reference/provider-contract.md) documents the extension contract for vulnerability sources.
- [Python API reference](reference/python-api.rst) is generated from source docstrings.
- [Local findings reference](reference/local-findings.md) defines the offline findings JSON format.
- [Architecture](explanation/architecture.md) explains the current trust boundary and processing flow.
- [Project status](explanation/project-status.md) explains what is usable now and what is still unstable before 1.0.
- [CI and recurring checks](development/ci.md) describes scheduled security gates and live-service check handling.

```{toctree}
:hidden:
:maxdepth: 2

tutorials/quickstart
tutorials/offline-local-findings
how-to/generate-cyclonedx-vex
how-to/use-private-osv-mirror
reference/cli
reference/cyclonedx-vex-output
reference/provider-contract
reference/python-api
reference/local-findings
explanation/architecture
explanation/project-status
development/ci
development/python-style
external/README
```
