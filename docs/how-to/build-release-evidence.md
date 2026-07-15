# Build and review self-release evidence

This runbook is for a Vexcalibur maintainer validating the local evidence
foundation for one exact commit. It creates files under `build/`; it does not
publish assets, change a GitHub Release, contact OSV, or require credentials.

## Prerequisites

Use a Linux checkout with:

- the exact `uv`, Node.js, `actionlint`, and `shellcheck` versions in
  `.tool-versions`.
- Python 3.14 for the repository validation environment.
- the Go version in `tests/integration/openvex-go/go.mod`.
- GNU Make, `sha256sum`, Git, npm, and a clean checkout of the target commit.
- no existing `build/release-evidence` directory.

Dependency installation and first-time Go or npm validator setup may contact
their configured package registries. VEX generation itself uses local files,
`--offline`, and unreachable proxy endpoints. Run the setup only on a host
where those public dependency fetches are allowed.

Do not put private SBOM data, embargoed advisories, tokens, customer
identifiers, or internal URLs in `release-evidence/`. These inputs and any
future generated assets are public by design.

## Validate the checked review

From the repository root, install the locked development and validator
dependencies:

```bash
uv sync --frozen
make csaf-validator-install
```

Confirm that `release-evidence/review.json` names the current lock digest:

```bash
sha256sum uv.lock release-evidence/findings.json
uv run --frozen python scripts/release_evidence.py validate-review \
  --review release-evidence/review.json \
  --findings release-evidence/findings.json \
  --lock uv.lock
```

For the initial snapshot, the sample success output is:

```text
production	0
```

Stop if a digest differs or the validator fails. Do not update a digest until a
maintainer has reviewed the corresponding full file.

## Build and exercise the installed wheel

Build once, select the single wheel, and run the complete fixture gate:

```bash
uv build --clear --no-create-gitignore --no-sources
mapfile -t wheels < <(find dist -maxdepth 1 -type f -name "*.whl" | sort)
test "${#wheels[@]}" -eq 1
export VEXCALIBUR_WHEEL="${wheels[0]}"
make release-evidence-check
```

The command generates both the production and synthetic bundles twice and
requires each recursive byte comparison to pass. The synthetic nonempty review
generates all formats, runs the official OpenVEX parser, runs the CSAF strict
schema and 42 mandatory tests, and compares cross-format assertions.

The final success line is:

```text
release-evidence production and synthetic fixture checks passed
```

The checker uses temporary directories and removes them on exit.

## Generate the inspectable bundle

Set `SOURCE_DATE_EPOCH` from the target commit. The generator also derives this
value and rejects a mismatch, so exporting it is an explicit operator check:

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export RELEASE_SHA="$(git rev-parse --verify HEAD)"
RELEASE_EVIDENCE_OUTPUT=build/release-evidence make release-evidence
```

For a zero-finding production review, verify the exact file set:

```bash
find build/release-evidence -maxdepth 1 -type f -printf '%f\n' | sort
```

Sample output:

```text
SHA256SUMS
findings.json
manifest.json
review.json
runtime-constraints.txt
sbom.cdx.json
vex.cdx.json
```

`vex.openvex.json` and `vexcalibur-vex.json` must not exist when the assertion
count is zero. Confirm the manifest decision and checksum integrity:

```bash
python - <<'PY'
import json
from pathlib import Path

manifest = json.loads(Path("build/release-evidence/manifest.json").read_text())
assert manifest["review"]["assertion_count"] == 0
assert manifest["formats"]["openvex"]["status"] == "omitted"
assert manifest["formats"]["csaf"]["status"] == "omitted"
assert manifest["intended_use"] == "release_evidence_candidate"
assert manifest["source_tree_clean"] is True
PY
uv run --frozen python scripts/release_evidence.py verify-bundle \
  --bundle-dir build/release-evidence
(
  cd build/release-evidence
  sha256sum --check SHA256SUMS
)
```

Every command must exit zero. Retain the bundle only as a local validation
artifact; this tranche does not define or authorize a publication step.

## Update the reviewed findings

Use this procedure only for public, reviewed findings. A discovered advisory is
not evidence for a stronger exploitability status.

1. Add one local-finding object to `release-evidence/findings.json`. Set
   `analysis_state` explicitly to `in_triage`, identify exactly one component by
   PURL or component reference, use a public source URL, and explain that impact
   analysis remains underway.
2. Review the complete findings file, then compute its SHA-256 digest.
3. Increment `analysis_revision` in `release-evidence/review.json`. Update
   `reviewed_at`, `reviewed_by`, `findings.sha256`, and `conclusion`.
4. If `uv.lock` changed, review the complete new lock and update
   `inventory.sha256`. The review cannot be carried across lock bytes without a
   new revision.
5. If the synthetic fixture's selected dependency changed, update its PURL and
   both fixture digests. Keep the fixture synthetic and `in_triage`.
6. Repeat the installed-wheel fixture gate and inspectable bundle steps.

With a real reviewed finding, the inspectable bundle must include CycloneDX,
OpenVEX, and CSAF output. All three validators and the equivalence check must
pass before review.

## Recover from a failed run

| Failure | Response |
| --- | --- |
| Dirty-tree rejection | Commit or intentionally discard the unrelated work, then rebuild the wheel. Do not use a dirty result for release review. |
| `SOURCE_DATE_EPOCH` mismatch | Derive it again from the exact requested commit; do not substitute wall-clock time. |
| Lock or findings digest mismatch | Review the changed file and update the review as a new revision, or restore the reviewed bytes. |
| Missing, dirty, or mismatched wheel SCM metadata | Rebuild the wheel once from the exact clean target commit. Do not relabel or reuse an artifact from another commit. |
| Missing OpenVEX or CSAF tool | Install the pinned Go or npm prerequisites and rerun; do not mark validation as passed manually. |
| Cross-format mismatch | Keep every generated file unpublished, identify the renderer or comparison defect, and add a regression test before rerunning. |
| Existing or concurrently created output directory | Verify or remove only the generated `build/release-evidence` directory, then rerun. Final placement fails without nesting into or overwriting that directory. |

To roll back an input change, revert the reviewed JSON change with Git and
rebuild from the prior exact commit. Generated files under `build/` are ignored
and have no external side effect.
