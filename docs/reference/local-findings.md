# Local Findings Reference

Local findings let `vexcalibur generate` build VEX without contacting a vulnerability service. Use this format for offline workflows, private review outputs, or CI jobs that already have vulnerability and analysis data from another trusted source.

The file is JSON. Unknown fields are rejected.

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
      "analysis_detail": "Reviewed and not affected in this deployment."
    }
  ]
}
```

## Document Fields

- `findings`: array of finding objects. The array can be empty when the caller intentionally wants a no-finding VEX document from local data only.

## Finding Fields

- `id`: required vulnerability identifier.
- `component_ref`: component `bom-ref` from the SBOM. Required unless `purl` is provided.
- `purl`: package URL from the SBOM. Required unless `component_ref` is provided. If a package URL matches more than one SBOM component, use `component_ref`.
- `source_name`: finding source name. Defaults to `Local`.
- `source_url`: finding source URL. Defaults to `https://vexcalibur.dev/sources/local`.
- `modified`: optional ISO-8601 timestamp for the vulnerability update time. Naive timestamps are treated as UTC.
- `analysis_state`: CycloneDX VEX state. Defaults to `in_triage`.
- `analysis_detail`: human-readable analysis detail. Defaults to `Provided by local findings file; manual exploitability analysis required.`

Supported `analysis_state` values:

- `resolved`
- `exploitable`
- `in_triage`
- `false_positive`
- `not_affected`

## Matching Rules

`component_ref` is preferred because VEX `affects` entries refer to SBOM components by ref. When both `component_ref` and `purl` are provided, they must identify the same SBOM component.

`purl` matching is allowed when the package URL identifies exactly one SBOM component. If the same package URL appears under multiple component refs, Vexcalibur rejects the finding and asks for `component_ref`.
