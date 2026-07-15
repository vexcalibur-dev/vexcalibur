# CycloneDX VEX output

`vexcalibur generate` writes CycloneDX 1.6 JSON by default. Pass `--format cyclonedx` when an explicit selector helps automation. The renderer consumes normalized component identities and provider-neutral findings.

## Document fields

| Field | Value |
| --- | --- |
| `$schema` | `http://cyclonedx.org/schema/bom-1.6.schema.json` |
| `bomFormat` | `CycloneDX` |
| `specVersion` | `1.6` |
| `serialNumber` | A `urn:uuid:` value derived from referenced components, findings, and the document timestamp |
| `version` | `1` |
| `metadata.timestamp` | `--timestamp`, normalized to UTC; otherwise the current UTC time |
| `components` | Only components referenced by at least one finding |
| `dependencies` | Reference-only dependency records for emitted components |
| `vulnerabilities` | Findings grouped into CycloneDX vulnerability entries |

JSON keys are sorted. Indentation is two spaces. The file ends with a newline.

## Vulnerability grouping

One output entry represents findings that share all five values:

- vulnerability ID.
- source name.
- source URL.
- analysis state.
- analysis detail.

The entry's `affects` array contains the sorted, unique component references from that group. The same vulnerability ID produces separate entries when its source, state, or detail differs.

Each entry contains `id`, `bom-ref`, `source`, `references`, `analysis`, and `affects`. It includes `updated` when the source supplied a modified time.

The `references` array repeats the vulnerability ID and source. `bom-ref` is derived from the five grouping values.

## Referenced components

The `components` array contains components referenced by at least one finding. Each item carries its normalized identity fields when available. These include `bom-ref`, `type`, `name`, `version`, and package URL.

Every finding must refer to a component from the parsed SBOM.

An explicit empty local findings array produces empty `components` and `vulnerabilities` arrays. An unknown component reference stops rendering with `VexRenderError`.

## Analysis fields

OSV findings use:

```json
{
  "analysis": {
    "detail": "Detected by OSV; manual exploitability analysis required.",
    "state": "in_triage"
  }
}
```

Local findings accept these states:

- `resolved`
- `exploitable`
- `in_triage`
- `false_positive`
- `not_affected`

The local default state is `in_triage`. Its default detail is `Provided by local findings file; manual exploitability analysis required.`

CycloneDX ignores the format-specific `action_statement`, `impact_statement`,
`fixed_version`, and `remediation_category` evidence fields. They do not change
grouping, serialized content, or the document serial number. OpenVEX and CSAF
use selected fields under their stricter state mappings.

OSV findings use source name `OSV` and URL `https://osv.dev/`. Local findings default to source name `Local` and URL `https://vexcalibur.dev/sources/local`.

## Updated time

When a group contains `modified` timestamps, `updated` is the latest one. The field is omitted when none of the group's findings has a timestamp.

Naive local timestamps are interpreted as UTC. A trailing `Z` is normalized to a `+00:00` offset.

## Deterministic output

Pass `--timestamp` and control the finding input when repeatable output matters:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

The same SBOM, findings, and timestamp produce the same serialized JSON. The document UUID is stable for those inputs. The vulnerability references are stable for those inputs.

A fixed timestamp does not make live OSV data stable. The responses must also be controlled.
