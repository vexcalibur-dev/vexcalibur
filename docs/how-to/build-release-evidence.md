# Build and review local release evidence

Use this runbook to inspect Vexcalibur's schema-1 self-evidence for one exact
commit. The commands do not mutate GitHub, PyPI, or another external service:
they do not create a tag, GitHub Release, attestation, or package upload.

They do change the local checkout and tool caches. Expect `.venv/`, `dist/`,
`src/vexcalibur/_version.py`,
`tests/integration/csaf-validator/node_modules/`, the requested bundle under
`build/`, and uv, Go, and npm cache entries. Temporary evidence workspaces are
removed on exit. `make clean` removes the repository-generated build output and
validator installation; remove `.venv/` or prune tool caches separately only
when you no longer need them.

For the credentialed schema-2 publication path, use [Publish Vexcalibur to
PyPI](publish-to-pypi.md).

## Prepare a clean release checkout

Use Linux and the tool versions in `.tool-versions`. You also need GNU Make,
Git, `sha256sum`, the Go version selected by
`tests/integration/openvex-go/go.mod`, and the locked Node dependencies for the
CSAF validator.

From the repository root:

```bash
git status --short
test -z "$(git status --porcelain)"
uv sync --frozen
make csaf-validator-install
```

Stop if Git reports any path. A dirty checkout is not a release-evidence input.

Dependency setup may download exact packages. VEX generation uses the reviewed
local-findings provider, but this process is not a general network sandbox.

Everything under `release-evidence/` is intended to become public. Do not place
embargoed advisories, private SBOM data, tokens, customer identifiers, or
internal URLs there.

## Check the human-reviewed snapshot

Display the two digests that the review binds:

```bash
sha256sum uv.lock release-evidence/findings.json
uv run --frozen python scripts/release_evidence.py validate-review \
  --review release-evidence/review.json \
  --findings release-evidence/findings.json \
  --lock uv.lock
```

The initial zero-finding review prints:

```text
production	0
```

A digest mismatch is a review failure. Do not update `review.json` merely to
make the command pass; review the complete changed lock or findings file first.

## Build once and run the conformance gate

Build the exact clean commit, select the only wheel, and exercise both evidence
fixtures:

```bash
uv build --clear --no-create-gitignore --no-sources
mapfile -t wheels < <(find dist -maxdepth 1 -type f -name "*.whl" | sort)
test "${#wheels[@]}" -eq 1
export VEXCALIBUR_WHEEL="${wheels[0]}"
make release-evidence-check
```

The gate generates the production and synthetic bundles twice in distinct
temporary directories and compares every byte. It also:

- verifies clean, full-commit wheel SCM metadata;
- installs with exact hash-locked dependencies and a SHA-256-bound wheel URI;
- validates CycloneDX output;
- runs the pinned official OpenVEX parser;
- runs the pinned CSAF schema and mandatory-test suite; and
- compares normalized assertions across all generated VEX formats.

Success ends with:

```text
release-evidence production and synthetic fixture checks passed
```

The synthetic fixture is conformance data, not a vulnerability claim. Its
reserved `.test` URL and `review_kind: synthetic_fixture` prevent accidental
publication as production evidence.

## Create an inspectable schema-1 bundle

Make the commit-derived timestamp explicit and generate into a fresh directory:

```bash
export RELEASE_SHA="$(git rev-parse --verify HEAD)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
RELEASE_EVIDENCE_OUTPUT=build/release-evidence make release-evidence
```

For a zero-finding review, the file list is:

```text
SHA256SUMS
findings.json
manifest.json
review.json
runtime-constraints.txt
sbom.cdx.json
vex.cdx.json
```

Verify the bundle and its checksum inventory:

```bash
uv run --frozen python scripts/release_evidence.py verify-bundle \
  --bundle-dir build/release-evidence
(
  cd build/release-evidence
  sha256sum --check SHA256SUMS
)
```

Inspect `manifest.json`. For the empty production snapshot, require:

```bash
python - <<'PY'
import json
from pathlib import Path

manifest = json.loads(Path("build/release-evidence/manifest.json").read_text())
assert manifest["schema_version"] == 1
assert manifest["review"]["assertion_count"] == 0
assert manifest["formats"]["openvex"]["status"] == "omitted"
assert manifest["formats"]["csaf"]["status"] == "omitted"
assert manifest["source_tree_clean"] is True
PY
```

Do not upload this local bundle to an existing release. The release workflow
creates the broader schema-2 asset set from isolated jobs and refuses manual
replacement.

## Update public findings

Use this sequence only after a maintainer has reviewed a public finding:

1. Add the finding to `release-evidence/findings.json`. Select exactly one
   component, explicitly set `analysis_state` to `in_triage`, and provide a
   public source and honest analysis text.
2. Review the entire new file and calculate its SHA-256.
3. Increment `analysis_revision`; update `reviewed_at`, `reviewed_by`, the
   findings digest, and `conclusion` in `review.json`.
4. If `uv.lock` changed, review the entire lock and update its digest in the
   same new revision.
5. Run the complete conformance gate and inspectable-bundle checks again.

A nonempty production bundle must contain `vex.cdx.json`,
`vex.openvex.json`, and `vexcalibur-vex.json`. Do not promote a finding to
`resolved`, `exploitable`, `false_positive`, or `not_affected` until a separate
evidence and approval policy exists for that stronger claim.

## Recover from local failures

| Failure | Safe response |
| --- | --- |
| Dirty-tree rejection | Commit the intended change or remove unrelated local state, then rebuild |
| Timestamp mismatch | Derive the epoch from the exact commit again |
| Review digest mismatch | Review and revise the bound input, or restore the reviewed bytes |
| Wheel SCM mismatch | Rebuild once from the exact clean commit; never relabel another wheel |
| Constraint grammar failure | Regenerate from the committed lock; never remove hash or binary-only enforcement |
| Missing OpenVEX or CSAF validator | Install the pinned prerequisites and rerun |
| Cross-format mismatch | Keep all output unpublished, fix the renderer or comparator, and add a regression test |
| Output directory already exists | Verify or remove only that generated directory, then rerun; the generator never overwrites it |

Generated files have no external effect. Roll back reviewed-input changes with
a normal Git revert and rebuild from the resulting exact commit.
