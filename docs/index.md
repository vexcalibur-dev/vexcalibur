# Vexcalibur Documentation

Vexcalibur is a pre-alpha toolkit for producing and transforming Vulnerability Exploitability eXchange documents from SBOMs and vulnerability data sources.

The project is intentionally general-purpose. The current implementation focuses on CycloneDX JSON SBOM ingest, OSV-backed finding discovery, and CycloneDX 1.6 VEX output. Public OSV access is fail-closed: commands must opt in with `--allow-public-osv` before package URLs, versions, or SBOM-derived inventories are sent to `https://api.osv.dev`.

## Start Here

- [Quickstart tutorial](tutorials/quickstart.md) walks through generating a VEX document from the repository's public fixture SBOM.
- [Generate CycloneDX VEX](how-to/generate-cyclonedx-vex.md) covers task-oriented generation commands and source configuration.
- [CLI reference](reference/cli.md) lists the current command surface.
- [Python API reference](reference/python-api.rst) is generated from source docstrings.
- [Local findings reference](reference/local-findings.md) defines the offline findings JSON format.
- [Architecture](explanation/architecture.md) explains the current trust boundary and processing flow.

```{toctree}
:hidden:
:maxdepth: 2

tutorials/quickstart
how-to/generate-cyclonedx-vex
reference/cli
reference/python-api
reference/local-findings
explanation/architecture
development/python-style
external/README
```
