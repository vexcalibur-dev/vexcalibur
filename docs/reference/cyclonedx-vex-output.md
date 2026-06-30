# CycloneDX VEX Output Reference

`vexcalibur generate` emits CycloneDX 1.6 JSON. The renderer builds the document
from SBOM component identities and provider-neutral vulnerability findings.

## Document Shape

The output includes:

- `bomFormat: "CycloneDX"`
- `specVersion: "1.6"`
- `serialNumber`: a deterministic UUID when the component set, finding set, and
  timestamp are unchanged.
- `metadata.timestamp`: the provided `--timestamp` value normalized to UTC, or
  the current UTC time when no timestamp is provided.
- `components`: affected SBOM components only.
- `vulnerabilities`: VEX vulnerability entries grouped from findings.

The JSON is canonicalized with sorted keys, two-space indentation, and a final
newline.

## Determinism

Use `--timestamp` when tests, pull request reviews, or repeatable artifacts need
stable output:

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

With the same SBOM, findings, and timestamp, the renderer emits the same
`serialNumber`, vulnerability `bom-ref` values, field ordering, and JSON
formatting.

Live OSV data can change over time. A fixed timestamp does not make public OSV
results immutable unless the OSV responses are also controlled.

## Vulnerability Grouping

Vexcalibur groups findings into one CycloneDX vulnerability entry by this key:

- vulnerability ID
- source name
- source URL
- analysis state
- analysis detail

Findings with the same key share one vulnerability entry. The entry `affects`
array contains the sorted unique component refs for the grouped findings.

Findings with the same vulnerability ID but a different source, state, or detail
produce separate vulnerability entries. Their `bom-ref` values are derived from
the grouped vulnerability metadata.

## Affected Components

The output `components` array contains only components referenced by at least
one finding. A VEX document generated from an explicit empty local findings file
can therefore contain an empty `components` array and an empty
`vulnerabilities` array.

Every finding must reference a component from the parsed SBOM. Rendering fails
when a finding uses an unknown component ref.

## Analysis State And Detail

OSV-derived findings currently use:

- `analysis.state: "in_triage"`
- `analysis.detail: "Detected by OSV; manual exploitability analysis required."`

Local findings can provide these CycloneDX VEX states:

- `resolved`
- `exploitable`
- `in_triage`
- `false_positive`
- `not_affected`

When local findings omit `analysis_state`, Vexcalibur uses `in_triage`. When
they omit `analysis_detail`, Vexcalibur uses
`Provided by local findings file; manual exploitability analysis required.`

## Source Fields

Each vulnerability entry includes a CycloneDX `source` object and a matching
single-item `references` array.

OSV-derived findings use:

- `source.name: "OSV"`
- `source.url: "https://osv.dev/"`

Local findings default to:

- `source.name: "Local"`
- `source.url: "https://vexcalibur.dev/sources/local"`

Local findings files can override both fields with a non-empty source name and
an HTTP(S) source URL with a host.

## Updated Timestamp

When grouped findings include `modified` values, the vulnerability entry
`updated` field is the latest modified timestamp in that group. If no grouped
finding has a modified timestamp, the vulnerability entry omits `updated`.

Naive local findings timestamps are treated as UTC. Timestamp strings ending in
`Z` are normalized to `+00:00`.
