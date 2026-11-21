# Quality attributes and internal requirements

This page records the internal obligations that constrain behavior, releases,
and documentation. Read it before changing behavior or release processes,
alongside the relevant [architecture](overview.md) and public reference
contracts. The [planning guide](../planning/README.md) describes document
authority and the status of proposed work.

This is the canonical home for internal policy. Public interface details and
compatibility guarantees stay in their user-facing references; this page links
to them instead of defining a parallel contract. Requirement IDs and their
test mappings have not yet been assigned.

## Public data and network access

Never send SBOM content, package URLs, versions, or project inventory to a
public service without explicit consent. Public vulnerability services fail
closed. `query-osv` and `generate` require `--allow-public-osv` for
`https://api.osv.dev`; private OSV-compatible services use `--osv-url`.
Fetching a GitHub SBOM does not consent to a later public OSV query.

Public-endpoint checks account for case, trailing dots, and IDNA dot
normalization. An injected client remains subject to those checks when its URL
is knowable. Local-findings mode must not construct or query an OSV client.
Tests use fake clients unless marked `live`; normal tests and examples use
fixtures, fakes, private mirrors, or local findings. Run live tests only when
the change and test data are approved for public-service access.

See the [provider contract](../reference/provider-contract.md) and
[CLI reference](../reference/cli.md) for the public interfaces and network
behavior.

## Source and rendering boundaries

Keep first-party provider code in `sources/`. A provider returns domain
findings and does not render a VEX format. A renderer consumes domain values and
does not query a source. Keep format-specific mapping in its renderer; do not
silently treat source update times as statement revision times or analysis
prose as remediation guidance.

`vexcalibur.api` is the supported Python facade. Public examples and external
consumer tests must import through it. Other modules are implementation details
unless the facade re-exports a name. See the
[provider](../reference/provider-contract.md),
[renderer](../reference/renderer-contract.md), and
[Python API](../reference/python-api.rst) contracts, and the
[compatibility policy](../reference/compatibility.md).

## Documentation and supported behavior

Keep domain and product decisions ecosystem-neutral unless an issue narrows
the scope. Do not present planned inputs, providers, output formats, or other
behavior as available. Document changes to a CLI, Python API, output contract,
provider, or trust boundary, and treat documentation as a tested product
surface. Update affected living pages when implementation changes and keep
proposals separate from supported behavior.

## Version and release integrity

`setuptools-scm` derives versions from `vMAJOR.MINOR.PATCH` tags. Do not add a
literal project version or commit generated `src/vexcalibur/_version.py`.
The tag is the release: the release process must not commit to the repository
after calculating its version. That includes a version bump, changelog write-back,
or tag substitution into tracked files. Derive the version from the tag at
build time so the tagged commit identifies what ships.

This applies to documentation too. Do not write the current release version
into prose, install commands, or examples. Install commands are unpinned. A
pinning example may use a permanently true version, such as the first release,
and must say it illustrates the form. Give readers a command to compute the
current version when needed. Historical release and minimum-version references
are fine because they remain true.

Versions owned by another repository do not belong here. The GitHub Action
depends on Vexcalibur, not the reverse; its commit pins, inputs, and
compatibility declarations belong in `vexcalibur-dev/vexcalibur-action`.

Repository tags and published release assets are immutable. Any mutable alias
must be a branch, not a moving tag. Do not retag a release or rebuild unreviewed
artifacts for publication. The release workflow derives a
version from Conventional Commits and validates the exact `main` commit; the
`vexcalibur-dev-automation` GitHub App creates the tag and GitHub Release.
The PyPI workflow accepts only an automation-authored immutable release whose
tagged commit remains an ancestor of current `main`, and publishes through
Trusted Publishing. Do not add a manual upload path without a security review.
Follow the [release procedure](../contributing/publish-to-pypi.md) and see
the [release evidence explanation](self-release-evidence.md) and
[evidence reference](release-evidence.md).

## Governance checks

GitHub organization, repository, environment, and security settings follow
the read-only [governance policy](../contributing/github-governance.md). Run
`make governance-check` after changing those settings. The check must fail if
any required endpoint is inaccessible; do not add a stored administrator token
to CI to make it periodic.
