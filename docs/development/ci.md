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
| Native report behavior | Fail-closed source checks plus installed wheel and source distribution checks on Windows; report transactions and installed wheel and source distribution checks on macOS with Python 3.10 and 3.14 |
| Parser properties | Deterministic Hypothesis smoke profile with a five-minute bound |
| Packaging | Wheel and source distribution, installed `vexcalibur` and `vexy` entry points |
| OpenVEX | Generated and installed-wheel output through pinned `go-vex` 0.2.8 |
| CSAF | OASIS schema plus all 42 mandatory tests from pinned `@secvisogram/csaf-validator-lib` 2.0.27 on Node 24; installed wheel and source distribution checks on Python 3.10 and 3.14 |
| Local evidence | Schema-1 zero-finding and synthetic all-format bundles, generated twice and byte-compared |
| Documentation | Warning-free Sphinx build, published-schema check, rendered accessibility checks, and executable execution-report examples |
| Security | `pip-audit`, base-branch-aware secret scanning, and dedicated CodeQL/dependency-review workflows |

Ordinary non-scheduled CI runs the unprivileged publication contract in
publication-only mode. An untagged candidate gets an ephemeral local `v0.0.0`
tag; a rerun on a released commit uses that commit's single annotated release
tag. The contract uploads the lock-derived inventory, generated VEX documents,
and execution reports as GitHub Actions artifacts retained for 14 days. Its
caller explicitly sets `allow-public-evidence-upload: true`.

The unprivileged contract has no publication credentials. It does not create a
GitHub Release or perform a PyPI OIDC exchange.

During a release, the pinned Action runs one synthetic finding through
CycloneDX, OpenVEX, and CSAF. That check does not depend on the production
review's finding count, so a zero-finding release still exercises every report
format.

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

Execution-report changes have three native gates:

| Environment | Prerequisite | Command | Success signal |
| --- | --- | --- | --- |
| Linux or macOS source checkout | Python, plus `uv sync --frozen` | `uv run --frozen pytest -q tests/test_execution_report_destination.py tests/test_execution_report_destination_cli.py tests/test_execution_report_destination_locks.py tests/test_execution_report_hardening.py tests/test_generation_output.py tests/test_generation_output_concurrency.py tests/test_cli_execution_report.py` | Pytest exits `0`; Windows-only cases are skipped |
| Linux or macOS installed wheel | Bash, GNU Make, Python, and `uv` | `make installed-cli-check` | The script exits `0` after importing and running the installed wheel |
| Windows source checkout | PowerShell, Python, and `uv sync --frozen` | The commands below | The source checks, installed wheel check, and sdist-derived wheel check exit `0` |

On Windows, run the same fail-closed checks as CI. Then install the local wheel,
build another wheel from the sdist with the locked backend, and test both
installed distributions. The commands use a unique temporary directory and
remove it in `finally`:

```powershell
$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion -lt [Version]"7.3") {
  throw "PowerShell 7.3 or newer is required"
}
$PSNativeCommandUseErrorActionPreference = $true
$work = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
$dist = Join-Path $work "dist"
$buildRequirements = Join-Path $work "sdist-build-requirements.txt"
$buildVenv = Join-Path $work "sdist-build-venv"
try {
  New-Item -ItemType Directory -Path $dist | Out-Null
  uv run --frozen pytest -q `
    tests/test_execution_report_destination.py::test_native_windows_report_request_fails_closed `
    tests/test_cli_execution_report.py::test_native_windows_cli_fails_closed_for_report_and_keeps_normal_output
  uv build --out-dir $dist --no-create-gitignore --no-sources
  $wheels = @(Get-ChildItem -Path $dist -Filter *.whl)
  $sdists = @(Get-ChildItem -Path $dist -Filter *.tar.gz)
  if ($wheels.Count -ne 1) {
    throw "Expected exactly one wheel in $dist, found $($wheels.Count)"
  }
  if ($sdists.Count -ne 1) {
    throw "Expected exactly one sdist in $dist, found $($sdists.Count)"
  }
  $expectedVersion = (
    uv run --frozen python -c `
      "import importlib.metadata; print(importlib.metadata.version('vexcalibur'))"
  )
  uv export `
    --quiet `
    --frozen `
    --only-group sdist-build `
    --no-emit-project `
    --no-annotate `
    --output-file $buildRequirements
  uv venv $buildVenv
  $buildPython = Join-Path $buildVenv "Scripts/python.exe"
  uv pip sync `
    --require-hashes `
    --only-binary :all: `
    --python $buildPython `
    $buildRequirements

  $distributions = @(
    @{ Name = "wheel"; Path = $wheels[0].FullName },
    @{ Name = "sdist"; Path = $sdists[0].FullName }
  )
  foreach ($distribution in $distributions) {
    $installDistribution = $distribution.Path
    if ($distribution.Name -eq "sdist") {
      $wheelDir = Join-Path $work "sdist-wheel"
      New-Item -ItemType Directory -Path $wheelDir | Out-Null
      $previousVirtualEnv = $env:VIRTUAL_ENV
      try {
        $env:VIRTUAL_ENV = $buildVenv
        uv build `
          --wheel `
          --no-build-isolation `
          --offline `
          --python $buildPython `
          --out-dir $wheelDir `
          $distribution.Path
      } finally {
        if ($null -eq $previousVirtualEnv) {
          Remove-Item Env:VIRTUAL_ENV -ErrorAction SilentlyContinue
        } else {
          $env:VIRTUAL_ENV = $previousVirtualEnv
        }
      }
      $builtWheels = @(Get-ChildItem -Path $wheelDir -Filter *.whl)
      if ($builtWheels.Count -ne 1) {
        throw "Expected one wheel built from the sdist, found $($builtWheels.Count)"
      }
      $installDistribution = $builtWheels[0].FullName
    }

    $venv = Join-Path $work "installed-$($distribution.Name)"
    $requirements = Join-Path $work "runtime-$($distribution.Name).txt"
    uv export `
      --quiet `
      --frozen `
      --no-dev `
      --no-emit-project `
      --no-annotate `
      --output-file $requirements
    python scripts/append_locked_distribution_requirement.py `
      $installDistribution `
      $requirements
    uv venv $venv
    $python = Join-Path $venv "Scripts/python.exe"
    uv pip sync `
      --require-hashes `
      --only-binary :all: `
      --python $python `
      $requirements
    $env:VEXCALIBUR_EXPECTED_PYTHON = (
      & $python -I -c `
        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    )
    $env:VEXCALIBUR_EXPECTED_VERSION = $expectedVersion
    & $python tests/integration/check_installed_windows.py
  }
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
```

The native-command preference turns every nonzero `uv`, Python, and pytest exit
into a terminating error. The Windows contract rejects report requests without
changing either output. It then proves that ordinary generation works from the
wheel and from a wheel rebuilt offline from the sdist.

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
hosted pull-request runners because it verifies GitHub artifact IDs and
transport digests. An untagged candidate gets an ephemeral local `v0.0.0` tag;
a rerun on a released commit uses the existing annotated release tag. The
credentialless checkout never pushes or changes a tag, and its caller
explicitly permits uploads derived from this public repository.

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
publication-only mode runs just the immutable-asset contract. Both modes
require the caller to consent explicitly to uploading the dependency inventory
and generated evidence.

The release and recovery workflows also require the release-platform
contracts. They rerun the exact commit on Windows and macOS with Python 3.10
and 3.14, then install the exact wheel through the pinned companion Action on
every supported Python version. Publication assets are not finalized until
those jobs pass. Pull-request CI does not repeat that matrix inside its
unprivileged publication rehearsal because the parent CI workflow already
requires the same native checks.

The publication graph has five independent roles:

1. `build` checks out the exact source and verifies or creates the intended
   release tag on that commit without deleting or reassigning any existing tag.
   It hash-syncs the PEP 517 backend, builds offline with the commit-derived
   `SOURCE_DATE_EPOCH`, validates both archives, and exports their exact hashes.
2. `publication-inventory` does not download, install, or execute either
   distribution and does not invoke the Action. It exports strict constraints
   and a normalized SBOM from `uv.lock`, then prepares the reviewed oracle.
3. `direct-vex` has no repository checkout or GitHub permission. It installs
   the hash-bound wheel with the oracle constraints, then emits VEX files and
   their execution reports.
4. `action-vex` also has no checkout or GitHub permission. It runs the companion
   Action at a full commit and requires missing or incorrect wheel hashes to
   fail, including an unhashed source-distribution fallback attempt. A failed
   generation must remove its stale report. Successful generations emit the
   same VEX files and reports as the direct CLI.
5. `publication-assets` runs fresh with `contents: read` and `actions: read`. It
   verifies every producer artifact through GitHub's API and archive digest,
   independently reproduces the lock exports, validates each report's counts
   and document digest, requires direct/Action byte equivalence, runs official
   validators, and creates a fresh flat asset set.

Each source-distribution matrix cell also uses two environments. The first
hash-syncs the exact PEP 517 tools from the `sdist-build` lock group and builds
the candidate sdist into a wheel with `uv` in offline, no-isolation mode. The
second hash-syncs that derived wheel and the runtime dependencies into a clean
environment before running the installed CLI checks. This prevents an index
from selecting unreviewed build requirements during validation.

The canonical release build uses the same backend rule. It hash-syncs the
`sdist-build` group before the build, then disables build isolation and network
access. The release digests therefore bind artifacts produced by the reviewed
backend bytes, not another copy selected from an index during the build.

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
