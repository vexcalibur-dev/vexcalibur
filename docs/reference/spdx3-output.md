# SPDX 3 output

`vexcalibur generate --format spdx3` writes SPDX 3.0.1 JSON-LD. A controlled
timestamp and finding set produce repeatable output. Vexcalibur implements the
renderer without an SPDX runtime library.

Vexcalibur targets the
[SPDX 3.0.1 specification](https://spdx.github.io/spdx-spec/v3.0.1/) and its
security profile. Tests use the official JSON Schema for the JSON-LD
serialization, vendored and pinned under `tests/fixtures/schemas` with its
documented provenance and checksum.

## Document contract

| Field | Value |
| --- | --- |
| `@context` | `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` |
| `@graph` | One `CreationInfo`, one `SpdxDocument`, one `Agent`, one `Tool`, then packages, vulnerabilities, and assessment relationships |
| Element `spdxId` | `https://vexcalibur.dev/spdx3/<uuid>#<local-name>` with a content-derived UUID namespace |
| `CreationInfo.created` | `--timestamp` in UTC; otherwise the current UTC time |
| `CreationInfo.createdBy` | The `Agent` named by the required `--creator` value, trimmed at both ends |
| `CreationInfo.createdUsing` | A `Tool` element naming Vexcalibur and its version |
| `SpdxDocument.profileConformance` | `core`, `security`, `software` |
| `SpdxDocument.rootElement` | The assessment relationship IRIs |
| `SpdxDocument.element` | Every other element IRI in the graph |

JSON keys are sorted. Indentation is two spaces, and the file ends with a
newline.

The element namespace is UUIDv5 over the canonical document content rendered
with a fixed placeholder namespace. It covers the timestamp, creator, tool
version, packages, vulnerabilities, and relationships. A content change
creates a new element namespace instead of claiming to revise the same
document.

## State mapping

Vexcalibur findings use a provider-neutral state model based on CycloneDX.
SPDX 3 defines one relationship class per VEX status. Explicit evidence
fields prevent the renderer from guessing across the semantic differences.

| Vexcalibur state | SPDX relationship class | Relationship type | Additional field | Fidelity |
| --- | --- | --- | --- | --- |
| `resolved` | `VexFixedVulnAssessmentRelationship` | `fixedIn` | Explicit `fixed_version` | The field must match the emitted product package URL version. This confirms that the identified product contains a fix. |
| `exploitable` | `VexAffectedVulnAssessmentRelationship` | `affects` | Explicit `action_statement` | The SPDX status is broader. The original state remains in `security_statusNotes`. |
| `in_triage` | `VexUnderInvestigationVulnAssessmentRelationship` | `underInvestigationFor` | None | Direct. |
| `false_positive` | `VexNotAffectedVulnAssessmentRelationship` | `doesNotAffect` | Explicit `impact_statement` | Lossy. SPDX has no false-positive status or justification for it. The original state remains in `security_statusNotes`. |
| `not_affected` | `VexNotAffectedVulnAssessmentRelationship` | `doesNotAffect` | Explicit `impact_statement` | Direct status mapping. |

SPDX requires `security_actionStatement` on every affected relationship, which
matches Vexcalibur's own evidence rule for `exploitable`.

A not-affected relationship may carry a `security_justificationType` instead
of an impact statement. Vexcalibur does not infer a justification from prose;
it always requires and emits the impact statement. The SPDX justification
catalog has narrower meanings than the domain state names.

A finding's `remediation_category` is valid only for an `exploitable` finding.
SPDX has no machine-readable field for it, so it appears in
`security_statusNotes`.

## Relationship grouping

One assessment relationship represents findings that share these values:

- vulnerability ID.
- source name and URL.
- original analysis state.
- analysis detail.
- action statement.
- impact statement.
- fixed version.
- remediation category.
- source modification time.

The relationship's `from` names the vulnerability element, and `to` lists the
sorted product package IRIs from the group. A difference in a grouping value
can create another relationship when the product sets do not overlap.

One vulnerability and emitted product may have only one effective assertion.
Vexcalibur rejects nonidentical assertions for the same vulnerability ID and
product package URL. Identical duplicate findings collapse into one assertion.

## Product identity

Each referenced SBOM component becomes a `software_Package` element with a
`name`, `software_packageVersion`, and `software_packageUrl`. Components that
share a canonical versioned package URL collapse into one package element.

When a component has an unversioned package URL and a separate version,
Vexcalibur adds that version to the emitted package URL. This avoids applying
an assessment to every version of a package.

SPDX output rejects a component when both its package URL and separate version
lack a version. An unversioned product can match every package version, which
would make a component review too broad.

An SBOM `bom-ref` or SPDX identifier may not be an IRI. Vexcalibur uses it for
internal matching but does not copy it into the SPDX document.

## Vulnerability identity

Each distinct vulnerability ID becomes one `security_Vulnerability` element.
Its `externalIdentifier` uses type `cve` when the ID matches the CVE pattern
and `securityOther` otherwise. The identifier's `identifierLocator` lists the
sorted source URLs that reported the vulnerability.

When findings for one vulnerability come from several sources, the element
merges them. Per-source provenance stays on each assessment relationship in
`security_statusNotes`.

## Provenance and timestamps

SPDX has no structured fields for Vexcalibur's source name, source URL,
original state, or remediation category. The renderer preserves them in
`security_statusNotes` with the analysis detail. A fixed relationship also
records its confirmed fixed version there.

The local `modified` field describes the source record's update time. The
vulnerability element emits it as `security_modifiedTime` only when the
findings for that vulnerability report exactly one distinct time, because that
SPDX field describes the vulnerability record itself. The renderer never emits
it as a relationship `modifiedTime`, which would claim an assessment revision
time.

SPDX serializes timestamps at second precision in UTC. Sub-second input
timestamps are truncated in `created` and `security_modifiedTime`; the
full-precision source time remains in `security_statusNotes`.

## Validation rules

Rendering stops with `VexRenderError` when:

- the creator or tool version is empty.
- the finding list is empty.
- a finding references an unknown component.
- a finding package URL differs from its component.
- an emitted product package URL has no version.
- required finding text is empty.
- an `exploitable` finding lacks `action_statement`, or another state supplies it.
- a `false_positive` or `not_affected` finding lacks `impact_statement`, or another state supplies it.
- a `resolved` finding lacks `fixed_version`, or another state supplies it.
- `fixed_version` differs from the version in the emitted product package URL.
- a finding that is not `exploitable` supplies `remediation_category`.
- the same vulnerability and product have nonidentical assertions.
- component references are duplicated.

The repository vendors the official SPDX 3.0.1 JSON Schema from the built
specification site in `spdx/spdx-spec` at commit
`eafb25cea14118a1302916253772c87aa2aa560f`. Its SHA-256 is
`19d65705ee474fb99467b5e006e05cab61b561974da34ff0e4a188bcf039387c`.

Tests validate golden output with JSON Schema Draft 2020-12 and format checks.
The schema checks structure only; the renderer tests assert the SPDX
constraints that JSON Schema cannot express, such as the impact-statement
requirement on not-affected relationships.

## Specification agility

Vexcalibur pins the SPDX context URL, specification version, and vendored
schema instead of following mutable upstream branches.

Future SPDX changes stay inside `Spdx3JsonRenderer`. The other output formats
use their own renderers over the same atomic document boundary, without
changing source adapters or the default CycloneDX contract.
