# Local findings format

A local findings file supplies vulnerability and exploitability data without a network provider. The file must be UTF-8 JSON no larger than 5 MiB.

The top-level value is an object with one required `findings` array. Unknown fields are rejected. The array may contain at most 10,000 items and may be empty.

```json
{
  "findings": [
    {
      "id": "CVE-2026-0001",
      "component_ref": "component:django",
      "source_name": "Internal Review",
      "source_url": "https://security.example.test/vulns/CVE-2026-0001",
      "modified": "2026-01-01T00:00:00Z",
      "analysis_state": "not_affected",
      "analysis_detail": "The affected feature is disabled in this deployment."
    }
  ]
}
```

## Top-level field

| Field | Required | Type | Description |
| --- | --- | --- | --- |
| `findings` | Yes | Array | Zero to 10,000 finding objects. An empty array records that the local source supplied no findings. |

## Finding fields

| Field | Required | Default | Rules |
| --- | --- | --- | --- |
| `id` | Yes | — | Non-empty vulnerability identifier. |
| `component_ref` | One selector required | — | Non-empty component reference from the parsed SBOM. |
| `purl` | One selector required | — | Valid package URL that matches exactly one parsed component. |
| `source_name` | No | `Local` | Non-empty string. |
| `source_url` | No | `https://vexcalibur.dev/sources/local` | HTTP or HTTPS URL with a host. |
| `modified` | No | Omitted | ISO-8601 timestamp string. Naive values are treated as UTC. |
| `analysis_state` | No | `in_triage` | One of the states listed below. |
| `analysis_detail` | No | `Provided by local findings file; manual exploitability analysis required.` | Non-empty string. |

Supported `analysis_state` values are `resolved`, `exploitable`, `in_triage`, `false_positive`, and `not_affected`.

## Component matching

At least one of `component_ref` and `purl` is required.

For local CycloneDX input, `component_ref` is the component's `bom-ref`. For GitHub SPDX input, it is the package `SPDXID` when present and otherwise the package URL.

When both selectors appear, they must identify the same component. A package URL that appears under more than one component reference is ambiguous and rejected; use `component_ref` in that case.
