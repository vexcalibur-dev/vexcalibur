# Vexcalibur

Vexcalibur turns SBOM package inventories and vulnerability findings into VEX
documents. It reads CycloneDX files or a GitHub Dependency Graph SBOM,
collects findings from OSV-compatible services or local JSON, and writes
CycloneDX 1.6, OpenVEX 0.2.0, CSAF 2.0, or SPDX 3.0.1 JSON.

Public OSV access fails closed. Vexcalibur sends package URLs and versions to `https://api.osv.dev` only when a command includes `--allow-public-osv`.

Vexcalibur is pre-1.0. Pin an exact release and review the [project status](explanation/project-status.md) before depending on a public contract.

New here? [Install a release](install.md), then work through the
[quickstart](tutorials/quickstart.md).

## Using Vexcalibur

These pages are for people generating VEX documents rather than changing
Vexcalibur itself.

### Tutorials

Start here if you haven't used Vexcalibur before. Both work from a source
checkout rather than an installed release, so you get the same inputs and the
same output they describe.

- [Generate your first VEX document](tutorials/quickstart.md)
- [Write and use a local findings file](tutorials/offline-local-findings.md)

### How-to guides

One task each. Most call an installed `vexcalibur` against your own SBOM, so
follow [Install Vexcalibur](install.md) first if you haven't:

- [Generate CycloneDX VEX](how-to/generate-cyclonedx-vex.md)
- [Generate OpenVEX](how-to/generate-openvex.md)
- [Generate CSAF VEX](how-to/generate-csaf.md)
- [Generate SPDX 3 VEX](how-to/generate-spdx3.md)
- [Use a private OSV mirror](how-to/use-private-osv-mirror.md)

Three need a source checkout instead, because they run committed example
scripts or validate against the repository's schema:

- [Generate VEX from Python](how-to/use-python-api.md)
- [Generate an execution report from Python](how-to/generate-execution-report-from-python.md)
- [Consume a generation execution report](how-to/consume-execution-report.md)

### Reference

Field-by-field contracts for the command line, the Python API, the input and
output formats, and the two extension points.

- [Command-line interface](reference/cli.md)
- [Python API](reference/python-api.rst)
- [CycloneDX VEX output](reference/cyclonedx-vex-output.md)
- [OpenVEX output](reference/openvex-output.md)
- [CSAF output](reference/csaf-output.md)
- [SPDX 3 output](reference/spdx3-output.md)
- [Generation execution report](reference/execution-report.md)
- [Local findings format](reference/local-findings.md)
- [Vulnerability-source provider contract](reference/provider-contract.md)
- [VEX renderer contract](reference/renderer-contract.md)

### Explanation

Why Vexcalibur is built the way it is, and what it does and doesn't promise
yet.

- [Architecture and trust boundaries](explanation/architecture.md)
- [Project status and compatibility](explanation/project-status.md)

## Running Vexcalibur in CI

- [GitHub Actions](https://github.com/vexcalibur-dev/vexcalibur-action) uses the
  released companion Action to run Vexcalibur in a workflow.
- [CircleCI](https://github.com/vexcalibur-dev/vexcalibur-orb) documents its
  current release status in the Orb README. Treat any development reference as
  mutable and inspection-only. Do not import one into a project with
  environment variables, contexts, private source, or other credentials.

The GitHub Action's [compatibility
reference](https://github.com/vexcalibur-dev/vexcalibur-action/blob/main/docs/reference/compatibility.md)
explains how to resolve its latest tested commit and Vexcalibur package. [Orb
issue #22](https://github.com/vexcalibur-dev/vexcalibur-orb/issues/22) records
the plan for App-backed production automation.

## Contributing to Vexcalibur

Separate from the guides above: how this repository is tested, released, and
governed. The [contributor documentation](contributing/index.md) covers the
style policy, fuzzing guide, CI layout, governance checks, and release
runbooks.

```{toctree}
:hidden:
:maxdepth: 2

install
```

```{toctree}
:hidden:
:caption: Tutorials
:maxdepth: 2

tutorials/quickstart
tutorials/offline-local-findings
```

```{toctree}
:hidden:
:caption: How-to guides
:maxdepth: 2

how-to/generate-cyclonedx-vex
how-to/generate-openvex
how-to/generate-csaf
how-to/generate-spdx3
how-to/use-private-osv-mirror
how-to/consume-execution-report
how-to/use-python-api
how-to/generate-execution-report-from-python
```

```{toctree}
:hidden:
:caption: Reference
:maxdepth: 2

reference/cli
reference/python-api
reference/cyclonedx-vex-output
reference/openvex-output
reference/csaf-output
reference/spdx3-output
reference/execution-report
reference/local-findings
reference/provider-contract
reference/renderer-contract
```

```{toctree}
:hidden:
:caption: Explanation
:maxdepth: 2

explanation/architecture
explanation/project-status
```

```{toctree}
:hidden:
:caption: Contributing
:maxdepth: 2

contributing/index
```
