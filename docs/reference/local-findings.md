# Local Findings Reference

Local findings let `vexcalibur generate` build VEX without contacting a vulnerability service. Use this format for offline workflows, private review outputs, or CI jobs that already have vulnerability and analysis data from another trusted source.

The file is UTF-8 JSON. The top-level value must be an object, the `findings` array is required, and unknown fields are rejected. Files larger than 5 MiB or documents with more than 10,000 findings are rejected.

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

- `findings`: required array of finding objects. Use an explicit empty array when the caller intentionally wants a no-finding VEX document from local data only.

## Finding Fields

- `id`: required non-empty vulnerability identifier.
- `component_ref`: non-empty Vexcalibur component reference. Required unless
  `purl` is provided. For local CycloneDX input this is the component
  `bom-ref`. For GitHub Dependency Graph SBOM input this is the package
  `SPDXID` when present, otherwise the package URL.
- `purl`: non-empty package URL from the SBOM. Required unless `component_ref` is provided. If a package URL matches more than one SBOM component, use `component_ref`.
- `source_name`: non-empty finding source name. Defaults to `Local`.
- `source_url`: HTTP(S) source URL with a host. Defaults to `https://vexcalibur.dev/sources/local`.
- `modified`: optional ISO-8601 timestamp for the vulnerability update time. Naive timestamps are treated as UTC.
- `analysis_state`: CycloneDX VEX state. Defaults to `in_triage`.
- `analysis_detail`: non-empty human-readable analysis detail. Defaults to `Provided by local findings file; manual exploitability analysis required.`

Supported `analysis_state` values:

- `resolved`
- `exploitable`
- `in_triage`
- `false_positive`
- `not_affected`

## Matching Rules

`component_ref` is preferred because VEX `affects` entries refer to normalized
component identities by ref. When both `component_ref` and `purl` are provided,
they must identify the same SBOM component.

`purl` matching is allowed when the package URL identifies exactly one SBOM component. If the same package URL appears under multiple component refs, Vexcalibur rejects the finding and asks for `component_ref`.
