# OpenVEX output

`vexcalibur generate --format openvex` writes OpenVEX 0.2.0 JSON. A controlled timestamp and finding set produce repeatable output. Vexcalibur implements the renderer without an OpenVEX runtime library.

Vexcalibur targets the [OpenVEX 0.2.0 specification](https://github.com/openvex/spec/blob/7667061835da09300f913e26be10ee03c05e784d/OPENVEX-SPEC.md). Tests use the [official schema at commit `a68ccd1`](https://github.com/openvex/spec/blob/a68ccd19b15a9604d28ef66ebf33f27a772ba4ec/openvex_json_schema.json). The release tag predates that schema file, so the repository vendors and pins the later schema.

## Document contract

| Field | Value |
| --- | --- |
| `@context` | `https://openvex.dev/ns/v0.2.0` |
| `@id` | Content-derived `urn:uuid:` identifier |
| `author` | Required `--author` value, trimmed at both ends |
| `role` | Optional `--author-role` value |
| `timestamp` | `--timestamp` in UTC; otherwise the current UTC time |
| `version` | `1` |
| `tooling` | `Vexcalibur` |
| `statements` | One or more grouped findings |

JSON keys are sorted. Indentation is two spaces, and the file ends with a newline.

The identifier is UUIDv5 over the canonical document content before `@id` is added. It includes the timestamp, author, role, tooling, and statements. A content change creates a new document identifier instead of claiming to revise the same document.

## State mapping

Vexcalibur findings use a provider-neutral state model based on CycloneDX. OpenVEX has four statuses. Explicit evidence fields prevent the renderer from guessing across the semantic differences.

| Vexcalibur state | OpenVEX status | Additional field | Fidelity |
| --- | --- | --- | --- |
| `resolved` | `fixed` | Explicit `fixed_version` | The field must match the emitted product package URL version. This confirms that the identified product contains a fix. |
| `exploitable` | `affected` | Explicit `action_statement` | The OpenVEX status is broader. The original state remains in `status_notes`. |
| `in_triage` | `under_investigation` | None | Direct. |
| `false_positive` | `not_affected` | Explicit `impact_statement` | Lossy. OpenVEX has no false-positive status. The original state remains in `status_notes`. |
| `not_affected` | `not_affected` | Explicit `impact_statement` | Direct status mapping. |

Vexcalibur does not infer an OpenVEX justification from prose. The OpenVEX justification catalog has narrower meanings than the domain state names.

Each explicit evidence field is valid only for its listed states. Vexcalibur does not turn `analysis_detail` into an action or impact statement.

## Statement grouping

One statement represents findings that share these values:

- vulnerability ID.
- source name and URL.
- original analysis state.
- analysis detail.
- action statement.
- impact statement.
- fixed version.
- source modification time.

The statement contains sorted, unique products from the group. A difference in a grouping value can create another statement when the product sets do not overlap.

One vulnerability and emitted product may have only one effective assertion. Vexcalibur rejects nonidentical assertions for the same vulnerability ID and product package URL. Identical duplicate findings collapse into one assertion.

`vulnerability.name` contains the finding ID. Vexcalibur does not put the source URL in `vulnerability.@id` because a provider homepage may not identify a specific vulnerability.

## Product identity

Each referenced SBOM component becomes an OpenVEX product. The product `@id` and `identifiers.purl` contain the canonical package URL.

When a component has an unversioned package URL and a separate version, Vexcalibur adds that version to the emitted product URL. This avoids applying a statement to every version of a package.

OpenVEX output rejects a component when both its package URL and separate version lack a version. An unversioned product can match every package version, which would make a component review too broad.

An SBOM `bom-ref` or SPDX identifier may not be an IRI. Vexcalibur uses it for internal matching but does not copy it into the OpenVEX product.

This model treats each matched component as a product. Vexcalibur does not yet model a root product with affected subcomponents.

## Provenance and timestamps

OpenVEX has no structured fields for Vexcalibur's source name, source URL, or original state. The renderer preserves them in `status_notes` with the analysis detail. A resolved statement also records its confirmed fixed version there.

The local `modified` field describes the source record's update time. It appears in `status_notes`, but not in OpenVEX `last_updated`. The latter describes a document or statement revision and would claim a different event.

## Validation rules

Rendering stops with `VexRenderError` when:

- the author or optional role is empty.
- the finding list is empty.
- a finding references an unknown component.
- a finding package URL differs from its component.
- an emitted product package URL has no version.
- required finding text is empty.
- an `exploitable` finding lacks `action_statement`, or another state supplies it.
- a `false_positive` or `not_affected` finding lacks `impact_statement`, or another state supplies it.
- a `resolved` finding lacks `fixed_version`, or another state supplies it.
- `fixed_version` differs from the version in the emitted product package URL.
- the same vulnerability and product have nonidentical assertions.
- component references are duplicated.

The official schema requires at least one statement. Vexcalibur also requires every standalone statement to contain at least one product, which the current schema does not enforce.

Tests validate golden output with JSON Schema Draft 2020-12 and format checks. A separate gate parses the same golden with official `go-vex` 0.2.8, validates every statement, and exercises package URL matching.

## Specification agility

OpenVEX is still evolving. Vexcalibur pins the context, schema commit, and Go compatibility version instead of following mutable upstream branches.

The tagged 0.2.0 prose shows an unversioned context in places. The current official Go implementation emits the versioned context used here.

Future OpenVEX changes stay inside `OpenVexJsonRenderer`. CSAF can use another renderer without changing source adapters or the default CycloneDX contract.
