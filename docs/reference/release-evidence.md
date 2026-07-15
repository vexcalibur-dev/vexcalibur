# Release-evidence reference

This page defines Vexcalibur's repository-maintained evidence formats. They are
not part of the package's pre-1.0 Python API.

## Reviewed inputs

`release-evidence/review.json` and the synthetic conformance review use this
closed-world schema:

| Field | Constraint |
| --- | --- |
| `schema_version` | Integer `1` |
| `review_kind` | `production` or `synthetic_fixture` |
| `analysis_revision` | Positive integer, advanced for each review |
| `reviewed_at` | Extended RFC 3339 UTC timestamp ending in `Z` |
| `reviewed_by` | Nonempty public attribution; repository review history supplies provenance |
| `inventory.path` | `uv.lock` |
| `inventory.sha256` | Exact lock SHA-256 as four colon-delimited groups of 16 lowercase hexadecimal characters |
| `inventory.coverage` | `cross-platform-reference-runtime` |
| `findings.path` | `release-evidence/findings.json` for production or `tests/fixtures/release-evidence/findings.json` for the synthetic fixture |
| `findings.sha256` | Exact findings SHA-256 in the same grouped form |
| `policy.allowed_analysis_states` | Array containing only `in_triage` |
| `conclusion` | Nonempty review conclusion and qualifications |

Unknown and duplicate JSON keys are errors. `findings.json` follows the
[local-findings contract](local-findings.md), with additional evidence rules:

- its root contains only `findings`;
- every finding explicitly uses `in_triage`;
- every finding selects exactly one product by PURL or component reference;
- canonical vulnerability/product pairs are unique; and
- production source URLs and analysis text are suitable for public release.

After selector resolution, the reviewed assertion count must equal the
canonical CycloneDX assertion count. Equivalent PURL and component-reference
selectors cannot inflate the result.

Normal validation accepts only the production input path. The repository's
synthetic input is accepted only when `validate-review` or
`scripts/generate-release-evidence.sh` receives `--allow-synthetic`. Its local
manifest records `evidence_kind: synthetic_fixture` and
`intended_use: ci_conformance_only`; it is never eligible for a publication
inventory. Production local evidence records `evidence_kind: production` and
`intended_use: release_evidence_candidate`.

## Shared manifest records

Manifest SHA-256 values use 64 lowercase hexadecimal characters without the
review input's colon grouping. These record shapes are reused below:

| Record | Exact fields and meaning |
| --- | --- |
| Artifact | `name`, `sha256`, and nonnegative byte `size` |
| Release | `commit`, `purl`, `source_date_epoch`, `timestamp`, and `version` |
| Review summary | `analysis_revision`, `assertion_count`, `conclusion`, `findings_sha256`, `review_sha256`, and `state_counts` |

The release commit is a lowercase 40-character Git object ID. `purl` is
`pkg:pypi/vexcalibur@VERSION`; `timestamp` is the UTC value derived from the
nonnegative commit epoch. The review summary does not duplicate reviewer
attribution: `reviewed_by` and `reviewed_at` remain in the separately bundled
and hashed `review.json`. `assertion_count` is nonnegative, and `state_counts`
maps each analysis state to its count in sorted-key order; the current policy
therefore permits only `in_triage`, or an empty object for zero findings.

Every `formats` object has exactly `cyclonedx`, `openvex`, and `csaf`. A
generated record contains `artifact`, `assertion_count`, `conformance`, and
`status: generated`. The exact conformance values are:

| Format | Artifact | Conformance value |
| --- | --- | --- |
| CycloneDX | `vex.cdx.json` | `CycloneDX 1.6 schema passed` |
| OpenVEX | `vex.openvex.json` | `official OpenVEX Go parser passed` |
| CSAF | `vexcalibur-vex.json` | `CSAF 2.0 strict schema and mandatory tests passed` |

CycloneDX is generated even with zero assertions. In that case, each other
format record contains only `reason` and `status: omitted`, and
`omitted_formats` contains matching `{format, reason}` records. The reason is:

```text
SPECIFICATION requires at least one vulnerability finding; this reviewed snapshot contains zero findings and makes zero VEX assertions.
```

`SPECIFICATION` is `OpenVEX 0.2.0` or `CSAF 2.0 VEX profile`.

## Local bundle: manifest schema 1

`scripts/generate-release-evidence.sh` creates a local bundle. Every bundle
contains:

| File | Contract |
| --- | --- |
| `sbom.cdx.json` | Normalized CycloneDX 1.5 reference-runtime SBOM |
| `runtime-constraints.txt` | Exact, hash-locked runtime requirements |
| `review.json` | Byte-identical reviewed input |
| `findings.json` | Byte-identical reviewed input |
| `vex.cdx.json` | CycloneDX 1.6 VEX, including a valid zero-assertion document |
| `manifest.json` | Schema-1 release, review, format, generator, validation, and artifact records |
| `SHA256SUMS` | Sorted digest inventory for every other file |

A nonempty review also produces `vex.openvex.json` and
`vexcalibur-vex.json`. Empty reviews omit them as described above.

The generated manifest has exactly these top-level fields:

| Field | Exact contract |
| --- | --- |
| `schema_version` | Integer `1` |
| `evidence_kind` | The reviewed input's `production` or `synthetic_fixture` kind |
| `intended_use` | `release_evidence_candidate` for production or `ci_conformance_only` for a synthetic fixture |
| `source_tree_clean` | Boolean recorded at generation; `false` is explicitly non-publishable |
| `release` | Shared release record |
| `inventory` | `coverage`, `limitation`, `lock_sha256`, `sbom`, and `sbom_specification` |
| `generator` | `distribution`, `version`, `wheel_filename`, `wheel_sha256`, `wheel_source_commit`, `wheel_source_dirty`, and `uv_version` |
| `review` | Shared review-summary record |
| `formats` | Exact format records described above |
| `omitted_formats` | Empty array or the required OpenVEX and CSAF omission records |
| `validation` | Exact validation record below |
| `artifacts` | Filename-sorted artifact records for every payload file, excluding `manifest.json` and `SHA256SUMS` |

The inventory values are
`coverage: cross-platform-reference-runtime`,
`sbom: sbom.cdx.json`, and
`sbom_specification: CycloneDX 1.5`. `limitation` is:

```text
uv.lock records the project's cross-platform reference runtime; it is not a claim about every environment-specific consumer resolution.
```

The generator values include `distribution: vexcalibur`, the installed package
version, the wheel filename and digest, its exact clean source commit,
`wheel_source_dirty: false`, and the uv version. The validation record has
exactly these fields and values:

| Field | Value |
| --- | --- |
| `cross_format_assertion_equivalence` | `passed`, or `not_applicable_without_assertions` for an empty review |
| `installed_local_wheel` | `passed` |
| `production_state_policy` | `only_in_triage` |
| `sbom_cyclonedx_1_5_schema` | `passed` |
| `vex_cyclonedx_1_6_schema` | `passed` |
| `vulnerability_provider_selection` | `offline_local_findings_only` |

This manifest binds one wheel and commit but does not claim that publication
occurred.

## Publication inventory: manifest schema 1

The release workflow transports a second schema-1 manifest before finalization.
It is a candidate-free oracle, not a local evidence manifest or a published
release asset. Its directory contains exactly `findings.json`, `review.json`,
`runtime-constraints.txt`, `sbom.cdx.json`, `uv.lock`, `manifest.json`, and
`SHA256SUMS`.

Its manifest has exactly `artifacts`, `inventory`, `inventory_kind`, `release`,
`review`, `schema_version`, `source_tree_clean`, and `uv_version`. The exact
constraints are:

- `schema_version` is `1`, `inventory_kind` is `publication_oracle`, and
  `source_tree_clean` is `true`;
- `release` and `review` use the shared record shapes;
- `inventory` contains the same coverage, limitation, SBOM name and
  specification as the local manifest, plus `lock: uv.lock` and the digest of
  that bundled lock;
- `artifacts` contains sorted records for the five inventory payload files; and
- `uv_version` is a nonempty string.

Only production reviewed inputs can create this inventory. The finalizer copies
the five payload files into the publication bundle, then replaces this transient
manifest and checksum inventory with the schema-2 records.

## Publication bundle: manifest schema 2

The reusable release-validation workflow creates one flat asset directory.
Every publication bundle contains:

| File | Contract |
| --- | --- |
| `uv.lock` | Exact reviewed lock bytes |
| `sbom.cdx.json` | Normalized CycloneDX 1.5 SBOM regenerated from that lock |
| `runtime-constraints.txt` | Strict runtime installation contract |
| `review.json` and `findings.json` | Exact reviewed inputs |
| `vex.cdx.json` | Byte-identical output from the installed wheel and pinned Action |
| `vexcalibur-VERSION-py3-none-any.whl` | Exact checked wheel later eligible for PyPI |
| `vexcalibur-VERSION.tar.gz` | Exact checked source distribution later eligible for PyPI |
| `manifest.json` | Closed-world schema-2 publication record |
| `SHA256SUMS` | Sorted digest inventory for every other release asset |

`vex.openvex.json` and `vexcalibur-vex.json` are additionally present when the
review contains at least one assertion.

The schema-2 verifier rejects unknown fields. The top-level fields are exactly:

| Field | Exact contract |
| --- | --- |
| `schema_version` | Integer `2` |
| `evidence_kind` | `production` |
| `intended_use` | `immutable_release_candidate` |
| `source_tree_clean` | Boolean `true` |
| `release` | Shared release record; tag must equal `vVERSION` |
| `inventory` | `coverage`, `limitation`, `lock`, `lock_sha256`, `sbom`, and `sbom_specification` |
| `review` | Shared six-field review-summary record |
| `generator` | Exact distribution record below |
| `formats` and `omitted_formats` | Exact generated or zero-assertion records described above |
| `validation` | Exact validation record below |
| `publication` | Exact publication and provenance record below |
| `artifacts` | Filename-sorted records for every asset except `manifest.json` and `SHA256SUMS` |

The inventory is the publication-inventory record, including `lock: uv.lock`.
The generator contains exactly `distribution`, `sdist_filename`,
`sdist_sha256`, `uv_version`, `version`, `wheel_filename`, `wheel_sha256`,
`wheel_source_commit`, and `wheel_source_dirty`. The distribution is
`vexcalibur`; the expected filenames are
`vexcalibur-VERSION.tar.gz` and
`vexcalibur-VERSION-py3-none-any.whl`; the source commit equals the release
commit; and `wheel_source_dirty` is `false`.

The schema-2 validation record contains the six schema-1 fields plus
`action_local_wheel_equivalence: passed`. All other values and the
zero-assertion cross-format exception are unchanged.

`publication` has exactly these fields:

| Field | Exact contract |
| --- | --- |
| `asset_contract` | `flat_immutable_github_release` |
| `release_tag` | Exact `vVERSION` tag |
| `payload_digest_algorithm` | `sha256_canonical_artifact_records_v1` |
| `distributions` | Exactly one sdist and one wheel record, each containing `kind`, `name`, `sha256`, and `size` |
| `build` | `actions_artifact_name: dist-COMMIT`, `job: build`, `payload_sha256`, and `workflow: .github/workflows/release-validation.yml` |
| `inventory` | `actions_artifact_name: release-inventory-COMMIT`, `job: publication-inventory`, and `payload_sha256` |
| `direct_generation` | `actions_artifact_name: direct-vex-COMMIT`, `job: direct-vex`, and `payload_sha256` |
| `action` | Exact Action provenance record below |

The `action` record contains exactly:

| Field | Value |
| --- | --- |
| `actions_artifact_name` | `action-vex-COMMIT` |
| `commit` | Full pinned companion Action commit |
| `constraints` | `runtime-constraints.txt` |
| `job` | `action-vex` |
| `output_equivalence` | `byte_for_byte` |
| `package_spec` | `file_uri_with_sha256_fragment` |
| `payload_sha256` | Canonical payload digest of the generated VEX files |
| `repository` | `vexcalibur-dev/vexcalibur-action` |

Schema-2 creation currently requires Action commit
`cc570fb0ab80df3f4b1e31c0608b95c0707d5b66`. Verification with an explicit
expected Action commit requires that exact value. Historical verification
without one accepts only a commit in the verifier's compiled allowlist for
schema 2; the manifest cannot extend that allowlist.

For each producer, the finalizer sorts the relevant
`{name, sha256, size}` records by filename, serializes them with the repository's
canonical JSON serializer, and records the SHA-256 as `payload_sha256`. The
inventory payload covers the five reviewed inventory files, the build payload
covers the wheel and source distribution, and the direct and Action payloads
cover the generated VEX files. The latter two digests must be equal.

GitHub Actions archive digests are checked while artifacts cross jobs. They are
deliberately absent from the published manifest because the archive envelope is
transport metadata and may differ on a recovery run.

## Runtime-constraint grammar

Both local and publication bundles use the same strict header:

```text
--require-hashes
--only-binary :all:

```

Every following logical requirement has an exact `name==version` pin and at
least one `--hash=sha256:...` continuation. Direct URLs, includes, index or
find-links directives, editable requirements, non-exact specifiers, and any
directive that weakens binary-only hash checking are rejected.

## Archive limits

Candidate archives are bounded before metadata is trusted:

| Limit | Value |
| --- | --- |
| Maximum evidence file | 32 MiB |
| Maximum archive members | 10,000 |
| Maximum total expanded archive size | 128 MiB |
| Maximum metadata member | 1 MiB |
| Maximum wheel SCM metadata | 64 KiB |

Absolute paths, parent traversal, duplicate members, links, devices, special
files, encrypted wheel entries, ambiguous metadata, and version/source
mismatches are errors.

## Integrity files

`SHA256SUMS` uses the GNU `sha256sum` form:

```text
LOWERCASE_SHA256__TWO_SPACES__FILENAME
```

Entries are filename-sorted. The checksum file includes `manifest.json` but not
itself. The manifest excludes itself and `SHA256SUMS`, avoiding a circular
digest while the checksum file binds the manifest to all other assets.

Verify a local schema-1 bundle:

```bash
uv run --frozen python scripts/release_evidence.py verify-bundle \
  --bundle-dir build/release-evidence
```

Verify a schema-2 publication bundle against an exact tag and commit:

```bash
RELEASE_TAG=v0.4.0
git fetch origin "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"
RELEASE_SHA="$(git rev-parse --verify "$RELEASE_TAG^{commit}")"

uv run --frozen python scripts/release_evidence.py verify-publication \
  --bundle-dir build/publication-assets \
  --release-tag "$RELEASE_TAG" \
  --release-sha "$RELEASE_SHA"
```

The schema-1 `verify-bundle` command checks that `SHA256SUMS`, manifest artifact
records, file sizes, and bundle bytes agree. It does not independently enforce
the generator's expected local schema-1 file set, rerun format validation, or
prove the semantic correctness of that manifest; generation and CI provide
those gates. `verify-publication-inventory` separately enforces the transient
schema-1 oracle contract.

Publication verification is deliberately stricter. It enforces the
closed-world schema-2 file and manifest contracts and rechecks reviewed inputs,
bundled-lock/SBOM semantics, runtime constraints, distribution metadata and SCM
identity, format decisions, stable payload digests, and production policy. The
release workflow separately reproduces lock-derived exports, runs the pinned
official OpenVEX and CSAF validators, and compares the GitHub-hosted asset bytes
after publication.

## Protected release-note tag payload

The release-note payload is not part of either evidence manifest. It is the
message of the protected bot-authored annotated release tag. The publisher
serializes one compact canonical JSON object with exactly these fields:

| Field | Constraint |
| --- | --- |
| `schema_version` | Integer `1` |
| `tag` | Exact `vMAJOR.MINOR.PATCH` release tag |
| `release_notes` | Exact secret-scanned release-note string |
| `release_notes_sha256` | SHA-256 of the UTF-8 release-note bytes as 64 lowercase hexadecimal characters |

The tag ref must point to an annotated tag object. That object must directly
target the expected release commit and name the automation bot's GitHub
noreply identity as tagger. Creation and immediate pre-publication checks
parse the closed JSON object and require its exact field values. JSON key order
or trailing whitespace is not a trust input; the embedded note bytes and digest
are.

Recovery reads the tag through GitHub's API, enforces the ref, object, target,
tagger, closed-world payload schema, tag value, and notes digest, and writes the
recovered note bytes from `release_notes`. If a draft or immutable release
already exists, its body must match those bytes. The recovered notes then pass
through the ordinary digest comparison and secret scan again. A mutable release
body is never accepted as the recovery authority.

## Repository CLI subcommands

`scripts/release_evidence.py` exposes these maintainer interfaces. Arguments in
brackets are optional; every other argument shown is required.

| Subcommand and arguments | Purpose |
| --- | --- |
| `timestamp --epoch INT` | Render a nonnegative epoch as the canonical UTC release timestamp |
| `normalize-sbom --input PATH --output PATH --release-version VERSION --timestamp TIME --lock-sha256 DIGEST` | Normalize one uv CycloneDX 1.5 export |
| `validate-review --review PATH --findings PATH --lock PATH [--allow-synthetic]` | Validate the reviewed inputs, bindings, and evidence policy |
| `validate-wheel --wheel PATH --release-sha COMMIT` | Verify clean, full-commit wheel SCM metadata |
| `hashed-file-uri --file PATH` | Print an absolute file URI with a SHA-256 fragment |
| `validate-cyclonedx --document PATH --spec-version {1.5,1.6}` | Validate a CycloneDX document against the selected bundled schema |
| `compare-formats --cyclonedx PATH --openvex PATH --csaf PATH` | Compare canonical assertions across all three VEX formats |
| `finalize --bundle-dir PATH --release-sha COMMIT --release-version VERSION --source-date-epoch INT --lock PATH --wheel PATH --review PATH --findings PATH --uv-version VERSION --source-tree-clean {true,false}` | Write and integrity-check a local schema-1 manifest and checksum file in a prepared staging directory |
| `verify-bundle --bundle-dir PATH` | Verify generic schema-1 checksum and artifact-record integrity |
| `prepare-publication-inventory --output-dir PATH --release-sha COMMIT --release-version VERSION --source-date-epoch INT --lock PATH --review PATH --findings PATH --constraints PATH --sbom PATH --uv-version VERSION --source-tree-clean {true,false}` | Create and verify the schema-1 publication oracle |
| `verify-publication-inventory --inventory-dir PATH --release-sha COMMIT --release-version VERSION` | Revalidate the oracle against an expected release identity |
| `finalize-publication --output-dir PATH --inventory-dir PATH --wheel PATH --sdist PATH --direct-output-dir PATH --action-output-dir PATH --release-tag TAG --action-commit COMMIT --expected-wheel-sha256 DIGEST --expected-sdist-sha256 DIGEST` | Assemble and verify the flat schema-2 asset set |
| `verify-publication --bundle-dir PATH --release-tag TAG --release-sha COMMIT [--action-commit COMMIT]` | Verify a complete schema-2 publication bundle |

`prepare-publication-inventory` and `finalize-publication` require a new output
directory and remove a partially created one after failure. The higher-level
`scripts/generate-release-evidence.sh` also refuses to replace its requested
local bundle directory. Verification commands do not create output directories;
`normalize-sbom` and `finalize` are lower-level writers and must be used only
with an intentionally prepared target.
