# Provider Contract Reference

Vulnerability providers convert SBOM component identities into
provider-neutral `VulnerabilityFinding` objects. The `vexcalibur generate`
workflow can then render those findings as CycloneDX VEX without knowing the
provider's request or file format.

## Interface

A provider implements `vexcalibur.domain.VulnerabilitySource`:

```python
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding


class ExampleSource:
    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        ...
```

`components` is the tuple returned by the SBOM loader. Each component includes:

- `ref`: CycloneDX `bom-ref`.
- `name`: component name.
- `version`: component version, or `None`.
- `purl`: parsed `packageurl.PackageURL`.
- `type`: CycloneDX component type string, defaulting to `library`.

The method returns zero or more `VulnerabilityFinding` objects.

## Finding Fields

Each finding must include:

- `id`: vulnerability identifier.
- `source_name`: provider or analysis source name.
- `source_url`: provider or advisory URL.
- `component_ref`: `bom-ref` from the parsed SBOM.
- `purl`: package URL string for the affected component.

Optional fields:

- `modified`: vulnerability update timestamp.
- `analysis_state`: CycloneDX VEX state. Defaults to `in_triage`.
- `analysis_detail`: human-readable analysis detail. Defaults to
  `Detected by vulnerability source; manual exploitability analysis required.`

The renderer rejects findings whose `component_ref` is not present in the parsed
SBOM component set.

## Errors

Use the shared error hierarchy so the CLI can report useful categories:

- Raise `VulnerabilitySourceInputError` when the SBOM components cannot produce
  provider-specific queries or matches. `generate` reports this as an SBOM
  ingest failure because the source cannot operate on the provided inventory.
- Raise a `VulnerabilitySourceError` subclass for provider configuration,
  network, response-shape, parsing, or local-file failures.
- Keep provider-specific subclasses when callers need to distinguish failures.

Do not leak provider stack traces to normal CLI users. The CLI catches known
source errors and prints category-prefixed failure messages.

## Trust Boundary

Network providers must make data sharing explicit. The OSV provider fails
closed for `https://api.osv.dev` unless the caller passes
`--allow-public-osv`, and it accepts private mirrors through `--osv-url`.

New public network providers should follow the same pattern:

- Identify the public default endpoint.
- Require an explicit opt-in before sending package URLs, versions, or
  SBOM-derived inventories to that endpoint.
- Support private or internal endpoints when the provider API can be mirrored.
- Document what package data leaves the local environment.

Offline providers should avoid constructing network clients and should make
local-file size, schema, and matching limits explicit.

## Provider Mapping

Provider-specific code belongs under `vexcalibur.sources`.

Recommended provider shape:

1. Validate provider configuration before sending requests or reading large
   files.
2. Convert `ComponentIdentity` values into provider-specific queries or lookup
   keys.
3. Validate provider responses or local documents before mapping findings.
4. Return sorted, immutable tuples when practical.
5. Let the shared renderer handle CycloneDX grouping, affected components, and
   VEX JSON formatting.

Avoid duplicating CycloneDX output rules in provider code. Providers should
produce `VulnerabilityFinding` objects and leave rendering to `vexcalibur.vex`.

## Tests

Provider changes should include focused tests for:

- configuration validation and fail-closed public-service policy;
- request or document parsing;
- pagination or repeated-token failures for network providers;
- invalid response or file shapes;
- mapping into `VulnerabilityFinding`;
- CLI error messages when the provider is reachable from a command.

Run the normal offline test suite before opening a provider pull request:

```bash
uv run --frozen python -m pytest -m "not live"
```

Run live tests only when the provider's public-service boundary has been
reviewed and the package data used by the test is safe to send.
