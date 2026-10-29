# Design: container distribution

> **Summary:** Should Vexcalibur distribute its CLI as a container as well as
> on PyPI? A Python slim image built from the verified release wheel is the
> leading proposal. The maintainer has not approved the registry, platforms,
> publication policy, or ongoing security work.

## Record

| Field | Value |
| --- | --- |
| Date | 2026-10-28 |
| Status | In review |
| Owner | Vexcalibur maintainer |
| Author | Codex |
| Related | [Release runbook](../contributing/publish-to-pypi.md); [self-release evidence](../architecture/self-release-evidence.md); [Orb image evaluation](https://github.com/vexcalibur-dev/vexcalibur-orb/issues/4) |
| Decision | Not decided |

## Problem

Today users install the CLI from PyPI into a Python environment. A container
could give automation a distribution with a known runtime and an immutable
digest, without requiring each consumer to assemble that environment. It also
adds an OS, a registry, another release path, and another security inventory
for the sole maintainer to support.

If nothing changes, PyPI remains the distribution path. The linked Orb issue
only evaluates possible later image integration; it is not a decision to use
an image or to change the Orb.

## Goals and non-goals

The proposed image should run the existing CLI with equivalent behavior,
retain the release's artifact identity, and be usable in constrained CI and
local environments. Its publication and recovery should be auditable without
replacing bytes behind a published identity.

This design does not implement an image or workflow, change the CLI, or
convert the companion Action to a container. Action conversion is deferred.
It does not establish an accepted ADR or authorize publication. Existing
PyPI distribution and its release process remain in place.

## Requirements in scope

The [internal requirements](../architecture/quality-attributes.md) are the
canonical source of contributor obligations. This design is constrained by
their public-data and network policy, source and rendering boundaries, and
version and release integrity rules. It does not define a second requirements
list. Requirement IDs and an accepted container ADR have not been assigned.

The following documents supply the detailed contracts this design relies on:

- The [release architecture](../architecture/self-release-evidence.md) and
  [evidence reference](../architecture/release-evidence.md) define the
  validated release artifacts used as image inputs.
- The [CLI reference](../reference/cli.md) defines inputs, outputs, failure
  behavior, credentials, and the offline and public OSV boundaries.
- The [execution report reference](../reference/execution-report.md) requires
  writable destination parents, persistent per-parent locks, and filesystem
  operations including advisory locking and directory `fsync`.

## Constraints

The tested Python range is 3.10 through 3.14; package metadata admits later
3.x versions. Select a tested interpreter for any image. The release bundle
contains constraints derived from the tagged `uv.lock`, including hashes and
binary-only enforcement. Those constraints can still require network access to
retrieve the permitted dependency bytes; they are not a deployed image SBOM.

The GitHub Release is immutable once published. An image pipeline must consume
it without adding assets to it or changing the tag, wheel, lock, or tracked
source. Existing GitHub and PyPI attestations and the Python inventory do not
prove the contents or provenance of an OS image.

## Options

### Keep PyPI only

Users install the published wheel and manage their own interpreter and runtime
dependencies. This preserves the existing release and privacy contracts and
adds no registry maintenance. It does not provide one digest for the complete
runtime; consumers remain responsible for the OS and environment they run.

### Python slim image

Use a digest-pinned Python slim base and install the verified release wheel
with the release-bound constraints. This matches the user's preference and
offers a familiar Python runtime with less packaging work than a custom
minimal image. It adds OS packages that need scanning and refresh, and its
size and multi-platform support still need measurement. The image must retain
CLI and privacy behavior; a smaller base alone does not establish either.

### Alpine or distroless image

Alpine may reduce size but its musl environment can change wheel availability
and require extra compatibility work. Distroless can reduce runtime tooling,
but Python assembly and diagnosis need more care. Either still needs the
same release-bound dependency, platform, runtime, and full-image security
evidence. Compare actual builds and native dependency coverage before
claiming either is smaller or safer for this project.

## Comparison

| Consideration | PyPI only | Python slim | Alpine or distroless |
| --- | --- | --- | --- |
| Consumer runtime | Consumer assembles it | Published runtime and digest | Published runtime and digest |
| Release identity | Existing verified wheel | Reuse that wheel; image needs separate evidence | Same, with additional assembly or compatibility work |
| Privacy and CLI | Existing contract | Must demonstrate parity | Must demonstrate parity |
| Maintenance | No image or OS inventory | Base and OS updates, registry and platform support | Same obligations; likely more validation or debugging effort |

## Recommendation

Recommend a Python slim image, with **`ghcr.io/vexcalibur-dev/vexcalibur`** and
**Linux amd64 and arm64** as proposals for maintainer approval. Confidence is
moderate: these choices fit the desired distribution and existing GitHub
release path, but no image has been built or measured. Platform availability,
runner costs, registry controls, and maintenance capacity could change the
recommendation. PyPI-only remains a reasonable choice if those costs are too
high.

### Release inputs and identity

The proposed image path branches from the same verified release as PyPI:

```text
immutable GitHub Release
  |-- existing PyPI publication
  `-- verify wheel and constraints
        -> build and test image
        -> stage image and evidence
        -> publish verified digest
```

The image path starts after a release is published and passes the eligibility
checks. PyPI publication is independent and need not block it. A manual
dispatch may recover an existing verified release, but must follow the
exact-byte recovery rules below, not blindly retag or rebuild an image.

After an eligible immutable GitHub Release exists, an image build should
independently check its automation-authored tag and release, target commit,
asset identities, attestations, and release bundle integrity as the PyPI path
does. Verify the wheel and release constraints against that bundle, and
verify the constraints against the tagged `uv.lock`. Install the exact
hash-bound wheel with those constraints and hash-checked, binary-only runtime
dependencies. Stop if an input is missing, unverifiable, or incompatible on
either platform; don't fall back to a source build or edit a version.

Use `uv` in a builder stage to install the released wheel non-editably into a
virtual environment, then copy that environment into a final stage with the
same pinned Python base and interpreter. Do not run project `uv sync` against
source. The final image needs no uv, compiler, `gh`, or runtime dependency
downloads. The [uv Docker guide](https://docs.astral.sh/uv/guides/integration/docker/)
describes the builder-stage and copied-environment approach. Pin the base by
digest because image tags can move, as [Docker's base-image guidance](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions)
explains. Pin and review builder tools separately.

Propose one immutable image tag derived from the full release Git tag, and
publish the multi-platform manifest and its platform digests as evidence.
Never publish `latest`, major, minor, or other moving aliases. Consumers can
pin the manifest digest; platform-specific consumers can record the selected
platform digest too. GitHub immutable releases protect Git releases and
assets, not OCI tags. There is no evidence here that GHCR enforces write-once
tags. Verify the registry controls before publication. If only a serialized
single publisher is available, prohibit overwrites operationally, treat the
digest as canonical, and present the residual overwrite risk to the
maintainer for explicit acceptance. A pre-push existence check alone is not
an atomic guarantee against concurrent publishers.

### Refresh and recovery

Base images and OS packages change after a release. Propose reviewed Renovate
base-digest updates, using `chore(deps)` to trigger a new package patch through
existing Conventional Commit automation. The repository's five-day minimum
release age is a waiting period, not a release cadence. Implementation would
need to enable Dockerfile updates in Renovate and verify how digest updates
are aged; don't assume a registry supplies the required timestamps.
Each refresh produces a new Git release, wheel, image,
and evidence; never mutate an existing image tag. A dedicated image revision
scheme could avoid releasing a new Python package for an OS-only change, but
adds a second version and recovery policy. The normal release is the simpler
first choice. The maintainer must approve the cadence, severity threshold,
response deadline, and warnings for affected old digests. Retaining old
immutable images does not make them safe to deploy indefinitely.

Build and verify an image before exposing its release tag. Retain the validated
manifest, layers, per-platform digests, and evidence in durable staging so an
interrupted publish can retry the *same bytes*. On retry, an absent tag may be
assigned only after confirming the target digest; a tag already pointing to
that digest is a verified no-op. A different digest, partial or ambiguous
registry state, missing staged bytes, or unverifiable evidence stops recovery.
Do not overwrite, delete, or rebuild under the same release tag to repair it.
If the exact bytes cannot be recovered, investigate and issue a new release
through the normal process. Prove these semantics with the chosen registry,
including concurrent attempts and manifest-list publication, before rollout.

### Runtime and privacy

Propose an exec-form CLI entrypoint with help as its default, and an optional
entrypoint override for `vexy` in the same image. Do not interpolate command
arguments through a shell. Test the default nonroot user with a read-only
root filesystem and dropped capabilities, as well as an arbitrary nonroot UID.

Input bind mounts should be readable by the selected UID; output and report parents must be
writable and support the operations in the execution report contract. Each
destination parent needs space for its persistent `.vexcalibur-locks`
directory and correctly owned lock files. Different UIDs sharing a destination
can encounter ownership failures; document and test that case rather than
weakening lock checks. A read-only root filesystem needs explicitly writable
temporary storage and output mounts. Do not assume the image can change host
mount ownership.

Keep offline local findings usable with networking disabled. Public OSV still
requires `--allow-public-osv`; selecting GitHub input is not that consent.
Private mirrors and GitHub input need only the network access users choose.
Pass a least-privilege GitHub token at runtime through the existing environment
option when needed, never in image layers, build arguments, labels, logs, or
published evidence. The proposed image excludes `gh`, so test and document
token-based access rather than assuming its authentication fallback exists.
Image pulls and build-time dependency downloads are separate from
the CLI's offline execution.

### Publication and evidence

Separate untrusted pull-request builds from release publishing. PR builds get
no registry write token or release secrets, and cannot promote their artifacts.
A protected release path should recheck the release and destination before
publication. No job with OIDC or write permissions should execute untrusted
artifacts. Propose a repository-linked package and `GITHUB_TOKEN` with
`packages: write` only in the publisher, without a new PAT or routine manual
approval. The [GitHub Container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
describes repository-linked publishing, the `org.opencontainers.image.source`
label, private first publication, anonymous pulls of public images, and digest
pinning. The owner must bootstrap and explicitly set the intended public
visibility, then verify an anonymous pull. Confirm package linkage and actual
permissions before selecting GHCR.

Produce image provenance tied to the release tag and commit, verified wheel
digest, constraints and lock digest, base digest, build inputs, builder, and
resulting manifest and platform digests. Generate and retain an SBOM for each
platform's full image, including OS packages and Python dependencies. Scan
those inventories and record results, exceptions, and tool identities. Verify
the provenance and SBOM against the published digests; the existing Python
release SBOM and release attestations are inputs, not full-image evidence.
The maintainer must approve where evidence lives, retention, scanner policy,
and how consumers verify it.

## Rollout and acceptance evidence

Each slice is contingent on maintainer approval; none requires changing the
Action or Orb.

1. **Feasibility:** build unpublished candidates for both proposed platforms.
   Record base and image sizes, wheel availability, native versus emulated
   test coverage, costs, and the registry's immutable-tag and recovery behavior.
2. **Runtime:** compare each image with the installed release wheel using
   fixed local fixtures and timestamps. Record CLI help, version, exit codes,
   stdout, file output, execution reports, and representative output formats.
   Check report digests and compare deterministic bytes where the CLI contract
   permits it. Exercise default nonroot and arbitrary UID, read-only root,
   dropped capabilities, bind mounts, writable temporary space, and lock
   ownership or unsupported filesystem failures.
3. **Trust and publication:** exercise tampered or missing release assets,
   mismatched lock constraints, untrusted PRs, denied registry writes,
   conflicting tags, interrupted pushes, concurrent retries, and missing
   staged bytes. Capture the manifest and per-platform digests, verified
   provenance, full-image SBOMs, scans, and recovery results.
4. **Network and release:** run local findings with networking disabled and
   prove no OSV client or network request is made. Test that public OSV without
   consent fails before a request, including after GitHub input; use fixtures
   or fakes, not public inventory. Test private and GitHub paths with controlled
   endpoints and runtime credentials. After review, publish and verify each
   platform by digest, then update user documentation and release procedures.

Acceptance requires passing evidence for both platforms and a documented
operator recovery procedure. A failed platform or missing security evidence
blocks the proposed multi-platform release; it is not silently omitted.

## Open questions

- Will the maintainer approve GHCR, its package visibility and permissions,
  and Linux amd64 plus arm64? Confirm registry controls, runners, and costs
  with a feasibility build.
- What immutable tag spelling and enforcement mechanism can GHCR support,
  including concurrent publication? Test its behavior and obtain maintainer
  acceptance of any residual overwrite risk before publication.
- Is a new Git release for every base refresh acceptable, and what cadence,
  severity thresholds, support window, and user warning policy apply? The
  maintainer must choose these before publication.
- Where will staged bytes, full-image SBOMs, provenance, scan results, and
  exceptions be retained and verified? The maintainer must approve a format,
  retention period, scanner policy, and recovery process.
- Does a tested slim Python version provide all hash-locked binary
  dependencies on both platforms, and do target filesystems support the report
  contract? Candidate builds and runtime tests must answer this.
- What durable decisions and living documentation should follow approval?
  The maintainer should choose their scope and location after review; no ADR
  or new requirement ID is assumed here.

## Outcome

Not decided. This proposal has not changed any runtime or publication behavior,
and no container ADR has been accepted.

- 2026-10-28: Initial proposal submitted for review; refined the registry,
  image build, refresh, and publication proposals.
- 2026-10-29: Linked the consolidated internal requirements and relocated
  release architecture; the container recommendation is unchanged.
