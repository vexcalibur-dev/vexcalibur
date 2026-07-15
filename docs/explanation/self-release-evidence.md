# Why Vexcalibur publishes evidence about itself

Vexcalibur should be able to describe its own vulnerability posture using the
same package and GitHub Action that downstream users run. That is useful only
if the evidence is tied to the release bytes. A VEX file generated from a
checkout while different bytes reach PyPI would be reassuring but meaningless.

The release design therefore treats the wheel, source distribution, locked
inventory, reviewed findings, direct CLI output, and Action output as one
immutable publication unit.

## Two bundles serve different purposes

The repository keeps two related contracts:

| Contract | Purpose | Published with a release |
| --- | --- | --- |
| Local bundle, manifest schema 1 | Fast, deterministic maintainer and CI checks of one installed wheel | No |
| Publication bundle, manifest schema 2 | Flat GitHub Release assets and the exact distributions later sent to PyPI | Yes |

The local bundle remains useful because it can be generated without release
credentials or GitHub state. The publication bundle adds isolation between
producers, companion-Action equivalence, source-distribution checks, immutable
release state, and recovery rules. Schema 2 extends the design; it does not
silently change what an old schema-1 manifest means.

## What is trusted

The design narrows trust instead of pretending to eliminate it:

| Input or service | Trusted claim | Important limit |
| --- | --- | --- |
| Exact Git commit | Source identity and commit-derived timestamp | A checkout alone does not identify published bytes |
| `uv.lock` | Cross-platform reference runtime reviewed at one digest | It is not an environment-specific deployed inventory |
| `review.json` and `findings.json` | Publicly reviewable finding snapshot and attribution | JSON cannot authenticate the reviewer or prove that no finding was missed |
| Wheel and source distribution | Exact package bytes and embedded version/source metadata | Archive validation does not prove the source code is benign |
| Pinned Vexcalibur Action commit | One reviewed wrapper implementation | The pin must be advanced deliberately when the Action changes |
| GitHub Actions and Releases | Job isolation, artifact transport, server-authenticated release and asset uploader identity, attestations, and immutable release enforcement | GitHub and the selected hosted-runner images remain part of the trusted platform |
| PyPI Trusted Publishing | OIDC-bound upload identity | PyPI availability and account governance remain external dependencies |

Production review policy currently permits only explicit `in_triage` findings.
An empty findings file means zero assertions. It never means that every
dependency is `not_affected`.

## Isolation is the main security boundary

The reusable release-validation workflow divides candidate handling across
fresh jobs:

```text
build ───────────────┐
                     ├──> fresh finalizer ──> flat release assets
inventory oracle ────┤
                     │
direct installed CLI ┤
pinned Action ────────┘
```

The inventory-oracle job never installs or executes the candidate wheel and
never invokes the companion Action. It exports strict hash-locked runtime
constraints and a normalized CycloneDX 1.5 SBOM from the exact lock, then binds
those files to the reviewed inputs.

The direct-generation job receives that oracle plus the exact wheel. It
installs the wheel with a SHA-256-bound local URI and runs the installed
`vexcalibur` entry point outside the checkout. The Action-generation job runs
the full-commit-pinned companion Action in a separate environment. Each job
emits only the files its consumer needs.

A fresh finalizer downloads all producer artifacts, verifies their GitHub
artifact identity and transport digests, revalidates every input, and requires
the direct and Action VEX files to be byte-for-byte equal. It writes into a
fresh directory and removes the incomplete directory after any late failure.
It never merges into or overwrites an existing output.

GitHub artifact archive digests protect transport within one workflow run, but
they are not stable publication data. The schema-2 manifest instead records
stable payload digests over filename-sorted `{name, sha256, size}` records.
That distinction keeps recovery runs byte-reproducible even if GitHub changes
the archive envelope.

## The evidence is deterministic

The release commit supplies `SOURCE_DATE_EPOCH` and every VEX timestamp. The
workflow builds once. The wheel must contain clean, full-commit SCM metadata;
the source distribution must contain the exact version and matching generated
SCM prefix. Both archive readers reject unsafe paths, duplicate members,
links, special files, oversized metadata, excessive member counts, and
excessive expanded size.

The bundled runtime constraints start with `--require-hashes` and
`--only-binary :all:`. Every requirement is an exact version with at least one
SHA-256 hash. This prevents dependency substitution; it does not mean package
installation is network-free. A runner may still download those exact bytes
from its configured index.

VEX generation itself selects only the reviewed local-findings provider. Proxy
settings provide an additional failure boundary, but the precise claim is
provider selection, not that every process on the runner lacks network access.

## Publication preserves the checked bytes

The release publisher verifies the validation artifact and every proposed
asset before it receives the short-lived write token. It accepts only a narrow
state machine: the tag is absent or is the exact bot-authored annotated tag for
the target; the release is absent, is an exact matching draft, or is the exact
already-published immutable release. Normal-mode idempotency may reuse the
exact release tag already at the current `main` tip. Recovering an older tag
requires the explicit recovery input.

The annotated tag also protects the release notes before the draft becomes
immutable. Its message is canonical, closed-world JSON containing the tag, the
exact secret-scanned notes, and their SHA-256. Recovery validates the tag ref,
object type, target commit, bot tagger, payload schema, and digest, then
reconstructs the notes from that protected object. An existing draft or release
body must match those bytes. The mutable draft body is therefore a checked
replica, not recovery's source of truth.

It never uploads with a clobber option. Existing assets must already match the
validated bytes. The only disposable marker is a zero-byte `state=starter`
asset created for the draft transaction. After publication, GitHub must report
the release immutable and the workflow verifies the release and each asset.

GitHub's API, rather than a self-authored manifest field, supplies each asset's
uploader identity. Reconciliation accepts a completed asset only when
`uploader.login` is `vexcalibur-dev-automation[bot]`. Immediately before the
immutable transition, the publisher snapshots every asset's ID, name, size,
state, uploader, and empty display label, downloads the bytes, and rejects any
metadata or byte change. It queries the immutable release again afterward and
requires the same bot uploader and empty label for every uniquely named,
completed asset.

Normal releases require the validated commit to remain the tip of `main`.
Manual recovery names an existing tag whose commit may be older, but that
commit must still be an ancestor of current `main`. Recovery therefore does
not break merely because unrelated commits landed after a partial release.

PyPI publishing downloads the wheel and source distribution from that exact
immutable GitHub Release. It does not rebuild. If neither file exists on PyPI,
both are uploaded; if one exact hash already exists, only the missing file is
selected. An existing filename with a different hash or package type stops the
workflow. The OIDC-bearing job receives only the already-checked subset and
uses no checkout, package installation, cache, or repository script.

PyPI publication independently queries the server-authenticated asset metadata
when it resolves the release, when validation downloads the asset set, and
immediately before the OIDC exchange. Every boundary requires a completed asset
uploaded by `vexcalibur-dev-automation[bot]` with no display label; an immutable
release authored by the bot is insufficient if even one asset has another
uploader or mutable UI label. Resolve and pre-OIDC checks also revalidate the
first-level bot-authored tag, notes envelope and digest, and exact release body.

## What the bundle does not prove

Self-release evidence does not replace an independent security assessment. It
does not prove that all vulnerabilities were discovered, authenticate the
human review field by itself, describe every consumer environment, or make an
`in_triage` assertion stronger than it is. It also does not make historical
releases immutable retroactively.

Those limits are intentional. The bundle is strongest when every recorded
claim is narrow enough to verify and every transition either preserves exact
bytes or fails closed.
