# Project status and compatibility

Vexcalibur has published releases and supports the workflows in this manual. It has not reached 1.0, so those releases do not yet promise a stable CLI or Python API.

Pin exact package and action versions in automation. Do not use a mutable branch for a production workflow.

## Published in version 0.3.1

- CycloneDX JSON and XML SBOM input for versions 1.4, 1.5, and 1.6
- GitHub Dependency Graph SBOM input through `--github-repo OWNER/REPO`
- public OSV queries with `--allow-public-osv`
- private OSV-compatible endpoints through `--osv-url`
- local findings with `--offline --findings-file`
- CycloneDX 1.6 VEX JSON output
- OpenVEX 0.2.0 JSON output with explicit author metadata
- CSAF 2.0 JSON output with the `csaf_vex` profile
- repeatable serialization when the SBOM, findings, and timestamp are controlled
- a limited `vexy` compatibility executable
- a released companion GitHub Action

The repository runs its Python, package, documentation, and deterministic
parser-property gates on every change. Supply-chain checks cover dependencies,
secrets, CodeQL, OpenSSF Scorecard, and a bounded weekly Atheris campaign.

OpenVEX goldens pass the pinned official schema and `go-vex` parser.

## Self-release evidence after version 0.3.1

Repository tooling can build a deterministic local schema-1 bundle and an
immutable-publication schema-2 bundle from the exact commit, locked reference
runtime, reviewed local findings, wheel, and source distribution. The
publication path requires byte-identical output from the installed package and
the full-commit-pinned companion Action. It publishes the same checked
distribution bytes to a flat immutable GitHub Release and then to PyPI through
Trusted Publishing.

Pull requests exercise the full schema-2 asset-generation and validation graph
without publication credentials or external publication. They do not perform a
real GitHub publication or PyPI OIDC exchange; those publisher paths are tested
statically until a real release. The initial production review makes zero
assertions; a separate synthetic `in_triage` fixture exercises CycloneDX,
OpenVEX, and CSAF equivalence.

This is maintainer and release tooling added after 0.3.1, not a new 0.3.1 package
API. Read [Why Vexcalibur publishes evidence about
itself](self-release-evidence.md) for its trust, isolation, and recovery
boundaries.

## CSAF conformance

CSAF output requires explicit publisher and tracking metadata. It also requires
precise versioned products and state-specific evidence. CSAF goldens and
installed-wheel output pass the pinned OASIS schema and mandatory semantic-test
suite.

## Unstable before 1.0

These surfaces may change between releases:

- command names, flags, defaults, messages, and exit behavior.
- Python imports, signatures, types, and exceptions.
- output details outside the documented CycloneDX, OpenVEX, and CSAF contracts.
- provider configuration and extension hooks.
- GitHub token lookup and Enterprise configuration.
- compatibility pairings between the package and its integrations.

Read release notes before upgrading, even across patch releases.

## Not implemented

Vexcalibur does not read VEX documents or convert between VEX formats.
OpenVEX and CSAF support is output-only.

CSAF 2.1, product branches and relationships, later document revisions,
trusted-provider metadata, distribution policy, and TLP are not implemented.

The release evidence is covered by GitHub's immutable-release and attestation
mechanisms. Vexcalibur does not yet produce a separate project-managed signing
format for VEX documents.

OSV findings do not yet pass through a policy engine that can decide deployment-specific exploitability. They use `in_triage` and require review.

The `vexy` adapter does not support legacy CycloneDX XML VEX output, CycloneDX 1.4 VEX output, or OSS Index credentials and queries.
