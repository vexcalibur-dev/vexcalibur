# Vulnerability-source provider contract

A provider turns normalized SBOM components into `VulnerabilityFinding` values. A built-in renderer adapts them into atomic assertions before it writes a format. Neither stage needs the provider's request or storage format.

The Python contract is pre-1.0 and may change between releases.

## Protocol

A source implements `vexcalibur.domain.VulnerabilitySource`:

```python
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding


class ExampleSource:
    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        ...
```

The method receives the complete normalized component tuple and returns zero or more immutable findings.

## Component identity

| Field | Type | Meaning |
| --- | --- | --- |
| `ref` | `str` | CycloneDX `bom-ref`, GitHub SPDX `SPDXID`, or a package URL fallback |
| `name` | `str` | Component name |
| `version` | `str \| None` | Component version when supplied |
| `purl` | `packageurl.PackageURL` | Parsed package URL |
| `type` | `str` | CycloneDX component type; defaults to `library` |

The effective component version comes from the PURL when the PURL is versioned. Otherwise it comes from `version`. When both fields supply a version, Vexcalibur compares the decoded PURL version with `version` and rejects the component unless they are equal. Percent encoding that decodes to the same version is not a conflict.

## Vulnerability finding

| Field | Type | Required or default | Meaning |
| --- | --- | --- | --- |
| `id` | `str` | Required | Vulnerability identifier. |
| `source_name` | `str` | Required | Provider or assessment source name. |
| `source_url` | `str` | Required | Provider or advisory URL with no username or password. CSAF requires an ASCII RFC 3986 HTTP(S) URI. |
| `component_ref` | `str` | Required | Reference copied from an input `ComponentIdentity`. |
| `purl` | `str` | Required | Canonical serialized package URL for that component. This is a string, unlike `ComponentIdentity.purl`. |
| `modified` | `datetime \| None` | `None` | Source update time. |
| `analysis_state` | `VexAnalysisState` | `VexAnalysisState.IN_TRIAGE` | VEX disposition for the component and vulnerability. |
| `analysis_detail` | `str` | `Detected by vulnerability source; manual exploitability analysis required.` | Human-readable analysis basis. |
| `action_statement` | `str \| None` | `None` | Remediation or mitigation guidance. OpenVEX and CSAF require it for `exploitable` findings. |
| `impact_statement` | `str \| None` | `None` | Deployment impact. OpenVEX and CSAF require it for `false_positive` and `not_affected` findings. |
| `fixed_version` | `str \| None` | `None` | Confirmed fixed product version. OpenVEX and CSAF require it for `resolved` findings. It must match the emitted product package URL version. |
| `remediation_category` | `VexRemediationCategory \| None` | `None` | Machine-readable remediation kind. CSAF requires it for `exploitable` findings; CycloneDX and OpenVEX ignore it. |

`remediation_category` accepts `mitigation`, `no_fix_planned`, `none_available`, `vendor_fix`, or `workaround`.

`component_ref` must equal a reference in the input component tuple. The built-in adapter rejects an unknown reference, a duplicate component reference, or a finding package URL that differs from its component.

Do not place credentials, signed-download secrets, or access tokens in `source_url`. The shared adapter and document boundary reject URL userinfo without copying it into an error. Query values are format-visible and are not a secret-storage mechanism.

OpenVEX and CSAF reject `action_statement`, `impact_statement`, and
`fixed_version` on states where they are not required. OpenVEX rejects
nonidentical assertions for one vulnerability and emitted product. CSAF groups
same-effective-status provenance and evidence, but rejects contradictory
effective statuses for that pair. CSAF also requires `remediation_category` on
`exploitable` and rejects it on other states. CycloneDX ignores all four
evidence fields.

The adapter retains `remediation_category`. CSAF serializes it as the category
of a product-scoped remediation. CycloneDX and OpenVEX do not serialize it, so
it does not change their grouping, content, or document identity.

An OpenVEX or CSAF product must have a version in its package URL or component
version field. Those renderers reject an assertion that would identify every
package version.

## Errors

Raise `VulnerabilitySourceInputError` when the component inventory cannot form valid provider queries or matches. The shared generation path reports this as an SBOM input error.

Raise a `VulnerabilitySourceError` subclass for configuration, network, response, parsing, or local-file failures. Keep a narrower provider exception when callers need to distinguish the failure.

Expected CLI failures should not expose Python tracebacks.

## Network boundary

A network source must make public data sharing explicit. At minimum, it should:

- identify its public endpoint.
- require consent before sending package URLs, versions, or an SBOM-derived inventory there.
- accept a private endpoint when the upstream API can be mirrored.
- document the data that leaves the runner.

The OSV source implements this policy with `--allow-public-osv` and `--osv-url`. A custom source passed to `generate_vex_from_source` owns its own network policy.

An offline source should not create a network client. It should define limits for local data and reject ambiguous component matches.

## Implementation shape

Provider code belongs under `vexcalibur.sources`.

1. Validate configuration before I/O.
2. Map `ComponentIdentity` values to provider queries or lookup keys.
3. Validate each response or local document.
4. Return `VulnerabilityFinding` values in stable order.
5. Leave assertion adaptation, grouping, and serialization to the selected renderer.

Do not duplicate output-format rules in a provider. For built-in formats, the document adapter owns shared identity checks. A renderer owns grouping, required evidence, and format-specific loss.

## Tests

Cover configuration, trust-boundary enforcement, parsing, invalid shapes, mapping, and CLI error reporting. A paginated network source also needs repeated-token and page-limit tests.

Run offline tests before opening a pull request:

```bash
uv run --frozen python -m pytest -m "not live"
```

Run live tests only with data approved for the provider's public endpoint.
