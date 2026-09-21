# Project status and compatibility

Vexcalibur is a released VEX toolkit with a command-line interface, a supported
Python API, and integrations for GitHub Actions and CircleCI. The workflows
below are implemented; the limits at the end of this page are intentional
boundaries, not features supplied by an integration.

The [compatibility policy](../reference/compatibility.md) defines the
guarantees for the CLI, Python facade, extension protocols, and generated
documents in the 1.x series. Earlier releases do not carry those guarantees.
Use the [release page](https://github.com/vexcalibur-dev/vexcalibur/releases)
to select a published version; this manual does not declare a release.

Pin exact package and action versions in automation. Do not use a mutable branch for a production workflow.

This manual follows the default branch, so it can describe a capability before
that capability reaches a package release. Execution reports were one such
capability: they reached release in v0.6.0. Check the documentation for
your release and its `vexcalibur generate --help` output before you update
automation.

GitHub Pages and Read the Docs both describe the default branch. For an
immutable contract, open the selected release tag on GitHub and use the
documentation and schemas from that tag.

## Capabilities on this branch

- CycloneDX JSON and XML SBOM input for versions 1.4, 1.5, and 1.6
- SPDX 3.0.1 JSON-LD SBOM input for local files
- GitHub Dependency Graph SBOM input through `--github-repo OWNER/REPO`
- public OSV queries with `--allow-public-osv`
- private OSV-compatible endpoints through `--osv-url`
- local findings with `--offline --findings-file`
- CycloneDX 1.6 VEX JSON output
- OpenVEX 0.2.0 JSON output with explicit author metadata
- CSAF 2.0 JSON output with the `csaf_vex` profile
- SPDX 3.0.1 JSON-LD output with the security profile's VEX relationships and
  explicit creator metadata
- repeatable serialization when the SBOM, findings, and timestamp are controlled
- bounded generation execution reports through the Linux and macOS CLI
  transaction or the cross-platform Python API
- a limited `vexy` compatibility executable
- a released companion GitHub Action
- a released CircleCI Orb

The repository runs its Python, package, documentation, and deterministic
parser-property gates on every change. Supply-chain checks cover dependencies,
secrets, CodeQL, OpenSSF Scorecard, and a bounded weekly Atheris campaign.

OpenVEX goldens pass the pinned official schema and `go-vex` parser. SPDX 3
goldens pass the pinned official JSON schema.

## Self-release evidence

Repository tooling can build a deterministic local schema-1 bundle and an
immutable-publication schema-2 bundle from the exact commit, locked reference
runtime, reviewed local findings, wheel, and source distribution. The
publication path requires byte-identical output from the installed package and
the full-commit-pinned companion Action. Each VEX document carries a validated
execution-report sidecar in the release. The workflow publishes the same
checked distribution bytes to a flat immutable GitHub Release and then to PyPI
through Trusted Publishing.

Pull requests exercise the full schema-2 asset-generation and validation graph
without publication credentials. An untagged candidate gets an ephemeral local
`v0.0.0` tag; a rerun on a released commit uses that commit's single immutable
release tag. The graph never pushes, moves, or deletes an existing tag. It may
remove the ephemeral local candidate if version verification fails. It uploads
only artifacts derived from this public repository, and the caller must set
`allow-public-evidence-upload: true`.

Pull requests do not create a GitHub Release or perform a PyPI OIDC exchange.
Offline integration tests execute the GitHub Release recovery transition. For
PyPI, they execute missing-file selection, publication-file verification, and
the final pre-OIDC release re-resolution with fake service clients. A real
release still verifies the live GitHub API, artifact actions, and PyPI OIDC
exchange. The current production review makes zero assertions; a separate
synthetic `in_triage` fixture exercises CycloneDX, OpenVEX, and CSAF equivalence.

This is maintainer and release tooling, not part of the public package API.
Read [Why Vexcalibur publishes evidence about itself](../contributing/self-release-evidence.md)
for its trust, isolation, and recovery boundaries.

## CSAF conformance

CSAF output requires explicit publisher and tracking metadata. It also requires
precise versioned products and state-specific evidence. CSAF goldens and
installed-wheel output pass the pinned OASIS schema and mandatory semantic-test
suite.

## Upgrade expectations

The compatibility policy covers documented behavior, not every implementation
detail. Human-readable diagnostics and help layout are not machine-readable
contracts. Python imports outside `vexcalibur.api` are internal, and generated
document bytes can change across package or dependency upgrades.

Retain a generated document and its execution report when exact bytes matter.
Read release notes before upgrading, including security fixes that reject
previously accepted unsafe input. The Action and Orb version independently;
check their documented package support when changing an integration pin.

## Not implemented

Vexcalibur does not read VEX documents or convert between VEX formats.
OpenVEX and CSAF support is output-only. SPDX 3 support covers VEX output and
local SBOM input; it still does not read SPDX VEX assessments.

CSAF 2.1, product branches and relationships, later document revisions,
trusted-provider metadata, distribution policy, and TLP are not implemented.

The release evidence is covered by GitHub's immutable-release and attestation
mechanisms. Vexcalibur does not yet produce a separate project-managed signing
format for VEX documents.

OSV findings do not yet pass through a policy engine that can decide deployment-specific exploitability. They use `in_triage` and require review.

The `vexy` adapter does not support legacy CycloneDX XML VEX output, CycloneDX 1.4 VEX output, or OSS Index credentials and queries.
