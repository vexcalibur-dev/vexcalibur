# CI, release, and recurring automation

Vexcalibur separates deterministic repository checks, untrusted candidate
execution, credentialed publication, and live-service compatibility. A failure
should identify which trust boundary broke instead of collapsing everything
into one privileged job.

## Pull requests and pushes

The `CI` workflow runs on pull requests and pushes to `main`:

| Area | Checks |
| --- | --- |
| Quality | Frozen lock, Ruff formatting and linting, strict MyPy |
| Tests | Offline suite on Python 3.10 through 3.14 |
| Parser properties | Deterministic Hypothesis smoke profile with a five-minute bound |
| Packaging | Wheel and source distribution, installed `vexcalibur` and `vexy` entry points |
| OpenVEX | Generated and installed-wheel output through pinned `go-vex` 0.2.8 |
| CSAF | OASIS schema plus all 42 mandatory tests from pinned `@secvisogram/csaf-validator-lib` 2.0.27 on Node 24 |
| Local evidence | Schema-1 zero-finding and synthetic all-format bundles, generated twice and byte-compared |
| Publication contract | Publication-only run using synthetic tag `v0.0.0` and only read-only, unprivileged `GITHUB_TOKEN` permissions; builds schema-2 assets but does not publish |
| Documentation | Warning-free Sphinx build |
| Security | `pip-audit`, base-branch-aware secret scanning, and dedicated CodeQL/dependency-review workflows |

The publication-contract caller grants only `contents: read` and
`actions: read`. The reusable workflow skips duplicate quality, matrix, and
documentation work in `publication-only` mode but still executes its build,
inventory, direct CLI, pinned Action, and fresh-finalizer boundaries. No App
token or PyPI OIDC permission exists in that path.

The `CI result` job combines all ordinary required results into the status
selected by the protected `main` ruleset. CodeQL, dependency review, and
pre-commit are separate required checks with strict up-to-date enforcement. See
[Verify GitHub governance](github-governance.md) for the organization-wide
policy and drift checks.

## Reproduce important gates

Run the complete offline test suite:

```bash
uv sync --frozen
uv run --frozen pytest -m "not live" --cov-fail-under=75
```

Run CSAF conformance:

```bash
make csaf-validator-install
make csaf-interop
make installed-csaf-check
```

Run the schema-1 self-evidence conformance gate with one local wheel:

```bash
uv build --clear --no-create-gitignore --no-sources
mapfile -t wheels < <(find dist -maxdepth 1 -type f -name "*.whl" | sort)
test "${#wheels[@]}" -eq 1
export VEXCALIBUR_WHEEL="${wheels[0]}"
make release-evidence-check
```

See [Build and review local release
evidence](../how-to/build-release-evidence.md) for input review, expected files,
and failure recovery. The full schema-2 graph is intentionally exercised on
hosted runners because it verifies GitHub artifact IDs and transport digests.

## Scheduled and live checks

The daily scheduled profile runs repository security checks plus tests marked
`live` against public services such as OSV and GitHub. A live failure may mean
an upstream outage, network problem, rate limit, or schema change; it does not
hide the independent dependency and secret results.

A normal manual `CI` run executes the pull-request profile. Set
`run_live_services` to add live tests. Set `run_scheduled_profile` to run only
the scheduled profile.

The separate weekly `Parser fuzzing` workflow runs bounded Atheris campaigns
against synthetic parser inputs with read-only repository permissions. It
uploads reproducers only after a failure and does not call vulnerability or
source-code services. The ordinary matrix excludes tests marked `fuzz`.

Reproduce approved live fixtures with:

```bash
make test-live
```

Do not send a private or customer-derived SBOM to a public provider merely to
reproduce CI.

## Reusable release validation

`.github/workflows/release-validation.yml` accepts an exact commit, tag, and
version. Its ordinary mode runs repository gates before publication jobs. Its
publication-only mode runs just the immutable-asset contract.

The publication graph has five independent roles:

1. `build` checks out the exact source, creates a temporary local release tag,
   builds once with commit-derived `SOURCE_DATE_EPOCH`, validates both archives,
   and exports their exact hashes.
2. `publication-inventory` does not download, install, or execute either
   distribution and does not invoke the Action. It exports strict constraints
   and a normalized SBOM from `uv.lock`, then prepares the reviewed oracle.
3. `direct-vex` has no repository checkout or GitHub permission. It installs
   the hash-bound wheel with the oracle constraints and emits only VEX files.
4. `action-vex` also has no checkout or GitHub permission. It runs the companion
Action at a full commit and requires missing or incorrect wheel hashes to fail,
including an unhashed source-distribution fallback attempt. It then emits only
VEX files from the correctly hash-bound wheel.
5. `publication-assets` runs fresh with `contents: read` and `actions: read`. It
   verifies every producer artifact through GitHub's API and archive digest,
   independently reproduces the lock exports, requires direct/Action byte
   equivalence, runs official validators, and creates a fresh flat asset set.

GitHub archive digests are same-run transport checks. The published schema-2
manifest records stable canonical payload digests so retrying validation for an
older recovery tag produces identical release assets.

The reusable outputs bind the exact wheel and source-distribution hashes, the
unique distribution and release-asset artifact names, the release-asset
`SHA256SUMS` digest, and transient artifact archive digests for their immediate
consumers.

## GitHub Release publication

`.github/workflows/release.yml` runs after a push to `main` or a manual
dispatch. Normal mode computes or accepts the next version and repeatedly
requires the target to equal the tip of `main`. Recovery mode accepts an
existing annotated `recovery-tag` whose commit is still an ancestor of `main`.

Release notes are generated, digest-bound, and secret-scanned across separate
runners. Two isolated jobs mint separate short-lived Contents-write App tokens:

- `generate-release-notes` has no checkout. Its token is used only to generate
  new notes or recover them from an existing protected annotated tag. Recovered
  notes cross the same digest and secret-scan boundary before publication.
- the publisher receives a different token only after validation, asset, and
  release-note checks pass. It has no checkout and does not execute repository
  code.

The publisher's bot-authored annotated tag embeds canonical schema-1 JSON with
the exact scanned release notes and their SHA-256. Tag validation binds the ref,
tag object, target commit, bot tagger, payload schema, notes digest, and release
tag. Recovery reconstructs notes from that protected tag and requires an
existing release body to match; it never treats a mutable draft body as the
source of truth.

The publisher accepts only that exact annotated tag and exact draft or immutable
published release state. It never uses asset clobbering. Completed existing
assets must match byte-for-byte and GitHub must identify their uploader as
`vexcalibur-dev-automation[bot]`; only a zero-byte `state=starter` marker in a
draft can be deleted during bounded recovery. Immediately before and after the
immutable transition, server-fetched snapshots bind every asset's ID, name,
size, state, uploader, and empty display label. Publication succeeds only after
GitHub reports the release immutable and the release and every asset pass
bounded verification.

## PyPI publication

`.github/workflows/pypi.yml` starts from a published release event or a manual
recovery tag. It requires an immutable, non-prerelease, automation-bot-authored
release whose first-level bot-authored annotated tag directly targets the
release commit, protects the exact release body, and is still an ancestor of
`main`.

A manual recovery must run from the exact requested tag. The workflow rejects
any mismatch between `github.ref` and its `release-tag` input, preserving the
GitHub environment's `v*` tag policy instead of letting one permitted ref name
authorize another release.

The validation job downloads the release assets, verifies attestations and the
schema-2 contract, independently re-exports the exact lock inventory, and runs
package, installed-wheel, OpenVEX, and CSAF checks. It queries the
version-specific PyPI JSON response and copies only missing distributions into
a fresh directory. Existing filenames must have the exact expected SHA-256 and
package type. Any unexpected file for that PyPI project version also stops the
run, even when the expected wheel and source distribution are present.

Release resolution, asset download/validation, and the immediate pre-OIDC check
each query GitHub independently and require every completed asset's
server-authenticated uploader to be `vexcalibur-dev-automation[bot]` and its
display label to be empty. Resolution and the pre-OIDC boundary also revalidate
the protected tagger, closed notes envelope, digest, and release-body bytes.

Only the final publisher has `id-token: write`. That job contains no checkout,
setup, cache, dependency installation, or repository script. It rechecks the
JSON filename subset, hashes, release identity, tag target, main ancestry, and
asset attestations immediately before the pinned Trusted Publishing action. If
both exact files already exist, a separate unprivileged job records a
successful no-op.

The Trusted Publisher identity is:

| Field | Value |
| --- | --- |
| Project | `vexcalibur` |
| Repository | `vexcalibur-dev/vexcalibur` |
| Workflow | `pypi.yml` |
| Environment | `pypi` |

Versions come from release tags through `setuptools-scm`. Never commit a
literal package version or generated `src/vexcalibur/_version.py`.

## Secret baselines

Pull requests scan tracked files against the base branch's
`.secrets.baseline`. A pull request cannot introduce a secret and suppress it
by editing the baseline in the same change.

```bash
make secrets       # current branch
make secrets-pr    # base-branch comparison
```

Refresh the baseline only in a dedicated, reviewed maintenance change:

```bash
make secrets-baseline
```

Prefer removing a value or adding a narrow inline allowlist for a demonstrated
false positive.

## Triage failures

| Failure | First response |
| --- | --- |
| Dependency audit | Confirm the advisory and upgrade while preserving supported Python versions; document impact if no fix exists |
| Secret scan | Remove or move the value; do not refresh the baseline in the introducing change |
| Installed CLI | Run `make installed-cli-check` and inspect `[project.scripts]` |
| OpenVEX | Distinguish parser/schema drift from a renderer defect; keep the official pin fixed while investigating |
| CSAF | Identify schema, mandatory semantic test, or filename-rule failure; do not weaken another layer to compensate |
| Publication artifact | Treat identity, digest, file-set, or byte mismatch as a supply-chain failure; never bypass it with clobbering |
| Immutable release | Use explicit recovery for the exact tag; do not edit the tag, notes, or completed assets manually |
| PyPI conflict | Stop; an existing filename with a different hash cannot be repaired by retrying |
