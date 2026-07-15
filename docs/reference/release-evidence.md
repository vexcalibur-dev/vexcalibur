# Release-evidence bundle reference

This reference defines the local self-evidence bundle produced by
`scripts/generate-release-evidence.sh`. The format is repository tooling, not a
stable pre-1.0 package API.

## Input contracts

`release-evidence/review.json` uses these fields:

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `schema_version` | Integer `1` | Review schema version. |
| `review_kind` | `production` | Prevents test fixtures from being mistaken for release inputs. |
| `analysis_revision` | Positive integer | Monotonic human-review revision. |
| `reviewed_at` | Extended RFC 3339 UTC date-time using `T` and ending in `Z` | When the snapshot was reviewed. |
| `reviewed_by` | Nonempty string | Claimed public review owner; repository history supplies provenance, while this field alone does not authenticate the reviewer. |
| `inventory.path` | Literal `uv.lock` | Canonical reference inventory input. |
| `inventory.sha256` | Four colon-delimited groups of 16 lowercase hexadecimal characters | Exact reviewed lock SHA-256; the validator removes group separators before comparison. |
| `inventory.coverage` | `cross-platform-reference-runtime` | Explicit inventory scope. |
| `findings.path` | Literal `release-evidence/findings.json` | Reviewed finding input. |
| `findings.sha256` | Four colon-delimited groups of 16 lowercase hexadecimal characters | Exact reviewed finding SHA-256; the grouping remains readable without resembling a secret token. |
| `policy.allowed_analysis_states` | Array containing only `in_triage` | Maximum permitted production claim. |
| `conclusion` | Nonempty string | Human-readable review result and qualification. |

The JSON parser rejects duplicate keys and unknown top-level fields. The
generator rejects a stale lock digest, stale findings digest, implicit analysis
state, duplicate canonical vulnerability-and-product assertions, or a finding
that identifies anything other than exactly one `component_ref` or `purl`.
Package URLs are canonicalized before duplicate comparison. After selector
resolution, the reviewed count must also equal the canonical CycloneDX output
count, so a component reference and equivalent PURL cannot inflate the manifest.

`findings.json` follows the [local findings reference](local-findings.md), with
these additional release policies:

- the root object contains only `findings`.
- every finding explicitly sets `analysis_state` to `in_triage`.
- each vulnerability and product pair appears once.
- all source URLs and analysis text are suitable for immediate public review.

## Generated files

Every bundle contains these files:

| File | Contents |
| --- | --- |
| `sbom.cdx.json` | Normalized CycloneDX 1.5 SBOM derived from the non-development `uv.lock` graph. |
| `runtime-constraints.txt` | Fully pinned, hashed runtime dependencies; it excludes the project wheel and has no temp-path header. |
| `review.json` | Byte-for-byte copy of the reviewed input. |
| `findings.json` | Byte-for-byte copy of the reviewed input. |
| `vex.cdx.json` | CycloneDX 1.6 VEX, including a schema-valid zero-assertion document. |
| `manifest.json` | Release identity, digests, scope, state counts, format decisions, and validation results. |
| `SHA256SUMS` | SHA-256 for every other bundle file, sorted by filename. |

When at least one reviewed finding exists, the bundle also contains:

| File | Contents and validation |
| --- | --- |
| `vex.openvex.json` | OpenVEX 0.2.0 accepted by the pinned official Go parser. |
| `vexcalibur-vex.json` | CSAF 2.0 `csaf_vex` document accepted by the strict schema and all 42 pinned mandatory tests. |

When findings are empty, those two optional files must be absent. Their
`formats` entries in the manifest have `status: omitted` and a reason stating
that the specification requires a finding while the reviewed snapshot makes
zero assertions.

## Manifest contract

`manifest.json` has `schema_version: 1` and these sections:

| Section | Required information |
| --- | --- |
| `release` | Exact 40-character commit, installed version and PURL, commit-derived timestamp, and integer `source_date_epoch`. |
| `inventory` | Lock digest, CycloneDX version, SBOM filename, reference-runtime scope, and its platform-selection limitation. |
| `generator` | Installed distribution and version, local wheel filename and digest, exact clean SCM source commit, and exact uv version. |
| `review` | Revision, conclusion, review and finding digests, assertion count, and counts by analysis state. |
| `formats` | Generated artifact or explicit omission for CycloneDX, OpenVEX, and CSAF. |
| `omitted_formats` | Scannable format-and-reason records; empty for a nonempty fixture. |
| `validation` | Schema, official-tool, equivalence, offline-source, installed-wheel, and production-policy results. |
| `artifacts` | Filename, size in bytes, and SHA-256 for every artifact except the manifest and checksum file. |

`intended_use` is `release_evidence_candidate` for a production review and
`ci_conformance_only` for a synthetic fixture. `source_tree_clean` records the
generator's exact cleanliness check. Neither field means publication has
occurred or that this foundation implements a publication mechanism.

## Checksum rules

`SHA256SUMS` uses the GNU `sha256sum` layout:

```text
LOWERCASE_SHA256__TWO_SPACES__FILENAME
```

Filenames use a restricted single-directory character set and entries are
sorted by filename. The checksum file includes `manifest.json` but cannot
include itself. The manifest's `artifacts` array excludes `manifest.json` to
avoid a circular digest; `SHA256SUMS` binds the manifest to the rest of the
bundle.

Verify checksum and artifact-record consistency from the repository root:

```bash
uv run --frozen python scripts/release_evidence.py verify-bundle \
  --bundle-dir build/release-evidence
(
  cd build/release-evidence
  sha256sum --check SHA256SUMS
)
```

Both commands must exit zero. The Python verifier rejects missing or duplicate
artifact records and checks every declared digest and byte size. It does not
rerun format schemas, validate every semantic manifest field, authenticate the
claimed reviewer, or establish the correctness of a human vulnerability
assessment. Those guarantees come from the generation gate, repository review
history, and—once implemented—the immutable publication provenance.
