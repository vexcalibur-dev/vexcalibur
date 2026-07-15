# Local findings format

A local findings file supplies vulnerability and exploitability data without a network provider. The file must resolve to a regular file and contain no more than 5 MiB of UTF-8 JSON. A symbolic link to a regular file is accepted. FIFOs, devices, sockets, directories, and links to those objects are rejected before content is read.

The top-level value is an object with one required `findings` array. Unknown fields and duplicate object keys at any depth are rejected. JSON may contain at most 100 nested arrays or objects, and an integer literal may contain at most 1,000 decimal digits. The array may contain at most 10,000 items.

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
      "analysis_detail": "The affected feature is disabled in this deployment.",
      "impact_statement": "The deployment does not enable the affected feature."
    }
  ]
}
```

## Top-level field

| Field | Required | Type | Description |
| --- | --- | --- | --- |
| `findings` | Yes | Array | Zero to 10,000 finding objects. CycloneDX accepts an empty array, but OpenVEX and CSAF output reject it. |

## Finding fields

| Field | Required | Default | Rules |
| --- | --- | --- | --- |
| `id` | Yes | — | Non-empty vulnerability identifier. |
| `component_ref` | One selector required | — | Non-empty component reference from the parsed SBOM. |
| `purl` | One selector required | — | Valid package URL that matches exactly one parsed component. |
| `source_name` | No | `Local` | Non-empty string. |
| `source_url` | No | `https://vexcalibur.dev/sources/local` | HTTP or HTTPS URL with a host and no username or password. CSAF output also requires ASCII RFC 3986 syntax. |
| `modified` | No | Omitted | ISO-8601 timestamp string. Naive values are treated as UTC. |
| `analysis_state` | No | `in_triage` | One of the states listed below. |
| `analysis_detail` | No | `Provided by local findings file; manual exploitability analysis required.` | Non-empty human-readable analysis. |
| `action_statement` | No | Omitted | Non-empty remediation or mitigation text. OpenVEX and CSAF require it for `exploitable` and reject it for other states. |
| `impact_statement` | No | Omitted | Non-empty impact text. OpenVEX and CSAF require it for `false_positive` and `not_affected`. They reject the field for other states. |
| `fixed_version` | No | Omitted | Non-empty version text. OpenVEX and CSAF require it for `resolved` and reject it for other states. It must match the emitted product package URL version. |
| `remediation_category` | No | Omitted | One of the remediation categories listed below. CSAF requires it for `exploitable` and rejects it for other states. |

Supported `analysis_state` values are `resolved`, `exploitable`, `in_triage`, `false_positive`, and `not_affected`.

Supported `remediation_category` values are `mitigation`, `no_fix_planned`, `none_available`, `vendor_fix`, and `workaround`.

Do not put credentials or secrets in `source_url`, including its query string. Vexcalibur rejects URL userinfo such as `user:password@host`. Query values may be serialized into every generated VEX format, so use an attributable public advisory URL rather than a signed or credential-bearing link.

CycloneDX output ignores `action_statement`, `impact_statement`, `fixed_version`, and `remediation_category`. These fields do not change CycloneDX grouping, content, or document identity.

OpenVEX ignores `remediation_category`. It does not change OpenVEX grouping,
content, or document identity. CSAF emits the category with a product-scoped
remediation and will not infer one from `action_statement` or
`analysis_detail`.

OpenVEX rejects nonidentical assertions for the same vulnerability ID and
emitted product package URL. Differences in source, state, analysis detail,
action statement, impact statement, fixed version, or modification time make
OpenVEX assertions nonidentical. CSAF groups provenance and evidence when the
effective product status agrees, including multiple action or impact objects,
but rejects contradictory effective statuses for the pair.

`modified` describes the source record. CycloneDX maps it to vulnerability
`updated`; OpenVEX keeps it in `status_notes`. CSAF keeps it in vulnerability
notes. Neither output treats it as a document or statement revision time.

OpenVEX and CSAF require a version in the emitted product package URL. They use
the component's separate version when the package URL is unversioned and reject
the assertion when both are unversioned.

CSAF maps `false_positive` and `not_affected` to the same
`known_not_affected` product status. It preserves the original state in notes
so consumers can see the lossy mapping. Read the [CSAF output
contract](csaf-output.md) for all state and evidence mappings.

## Component matching

At least one of `component_ref` and `purl` is required.

For local CycloneDX input, `component_ref` is the component's `bom-ref`. For GitHub SPDX input, it is the package `SPDXID` when present and otherwise the package URL.

When both selectors appear, they must identify the same component. A package URL that appears under more than one component reference is ambiguous and rejected; use `component_ref` in that case.
