# Vulnerability-source provider contract

A provider turns normalized SBOM components into `VulnerabilityFinding` values. Generation then renders those values without knowing the provider's request or storage format.

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

## Vulnerability finding

| Field | Type | Required or default | Meaning |
| --- | --- | --- | --- |
| `id` | `str` | Required | Vulnerability identifier. |
| `source_name` | `str` | Required | Provider or assessment source name. |
| `source_url` | `str` | Required | Provider or advisory URL accepted by the target renderer. |
| `component_ref` | `str` | Required | Reference copied from an input `ComponentIdentity`. |
| `purl` | `str` | Required | Canonical serialized package URL for that component. This is a string, unlike `ComponentIdentity.purl`. |
| `modified` | `datetime \| None` | `None` | Source update time. |
| `analysis_state` | `VexAnalysisState` | `VexAnalysisState.IN_TRIAGE` | VEX disposition for the component and vulnerability. |
| `analysis_detail` | `str` | `Detected by vulnerability source; manual exploitability analysis required.` | Human-readable basis or next action. |

`component_ref` must equal a reference in the input component tuple. The renderer rejects an unknown reference.

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
5. Leave grouping and serialization to `vexcalibur.vex`.

Do not duplicate CycloneDX rendering rules in a provider.

## Tests

Cover configuration, trust-boundary enforcement, parsing, invalid shapes, mapping, and CLI error reporting. A paginated network source also needs repeated-token and page-limit tests.

Run offline tests before opening a pull request:

```bash
uv run --frozen python -m pytest -m "not live"
```

Run live tests only with data approved for the provider's public endpoint.
