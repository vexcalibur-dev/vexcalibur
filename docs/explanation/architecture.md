# Architecture and trust boundaries

Vexcalibur separates package inventory, source access, provider findings, atomic assertions, and VEX rendering. Provider rules stay out of the output writer. Format rules stay out of network clients.

## Generation flow

```text
CycloneDX JSON/XML file       GitHub Dependency Graph SBOM
        |                                 |
        v                                 v
   sbom loader                    GitHub SBOM client
        |                                 |
        +----------------+----------------+
                         |
                         v
              ComponentIdentity values
                         |
                         v
           one VulnerabilitySource adapter
                  /                 \
                 v                   v
       OSV-compatible API      local findings JSON
                  \                 /
                   v               v
              VulnerabilityFinding values
                         |
                         v
                 selected VexRenderer
                   /             \
                  v               v
          custom renderer    built-in adapter
                  |               |
                  |               v
                  |          VexDocument
                  |      atomic assertions
                  |               |
                  |       +-------+-------+-------+
                  |       |               |       |
                  |       v               v       v
                  |  CycloneDX 1.6   OpenVEX   CSAF 2.0
                  |                   0.2.0      VEX
                  |       \               |       /
                  +--------+--------------+------+
                           |
                           v
                    VEX JSON document
```

The two inventory paths meet at `ComponentIdentity`. The two finding paths meet at `VulnerabilityFinding`. This remains the documented custom-renderer interface.

## Inventory boundary

`vexcalibur.sbom` handles local CycloneDX JSON and XML. A shared input reader opens each path once in nonblocking mode, verifies the opened target is a regular file, and reads no more than the configured limit from that descriptor. Symbolic links to regular files remain usable, while FIFOs, devices, and links to them fail before a read can block.

A shared JSON decoder rejects duplicate keys, excessive nesting, oversized integers, invalid UTF-8, and malformed syntax for CycloneDX, local findings, GitHub SPDX, and OSV responses. CycloneDX XML uses its hardened XML path. The inventory loaders also apply component-count, package URL, duplicate-reference, and XML checks before they return components.

`vexcalibur.github_sbom` handles GitHub's asynchronous Dependency Graph API. It requests the SPDX 2.3 JSON report and waits for the download. It then validates the response and extracts package URL references. Multiple equivalent references collapse to their canonical package URL; multiple distinct package URLs for one package are ambiguous and rejected. Both loaders produce the same component shape.

Components without package URLs do not cross this boundary. Source adapters need package identity, and a VEX `affects` entry needs a stable component reference.

The component model has one version rule across local files, GitHub SPDX, OSV queries, and rendering. A PURL version is authoritative when present. A separate CycloneDX `version` or SPDX `versionInfo` is the fallback for an unversioned PURL. When both exist, their decoded values must match.

## Finding-source boundary

A `VulnerabilitySource` receives all normalized components and returns `VulnerabilityFinding` values.

`OsvSource` builds version-specific OSV queries and maps matches to findings. `LocalFindingsSource` validates a JSON file. It matches each item by component reference or unique package URL.

Provider-specific request and parsing logic stays inside the adapter.

`VulnerabilitySourceInputError` means the inventory cannot form valid provider input. Other source failures inherit from `VulnerabilitySourceError`, with provider-specific subclasses for useful error categories.

## Document boundary

The built-in renderers adapt components and findings into an immutable `VexDocument`. Each `VexAssertion` connects one vulnerability to one product. Products keep their source component reference, so two SBOM components with the same package URL remain distinct.

The model uses four broad dispositions: `fixed`, `affected`, `under_investigation`, and `not_affected`. Qualifiers retain narrower provider meaning. For example, `exploitable` becomes `affected` with an `exploitable` qualifier, while `false_positive` becomes `not_affected` with a `false_positive` qualifier.

The adapter rejects duplicate component references, unknown references, finding package URLs that disagree with their component, contradictory product versions, and vulnerability source URLs containing userinfo. It removes exact duplicate assertions but keeps records that differ in source, state, analysis, or evidence. Each renderer decides whether its format can represent those records together.

This model represents generated snapshots only. Vexcalibur still does not read VEX documents or convert between formats.

The document model is an internal pre-1.0 seam. It is not yet a stable public API.

## Network boundary

An SBOM can expose internal package names, exact versions, and dependency choices. Vexcalibur does not treat a vulnerability lookup as harmless metadata access.

Public OSV fails closed until the caller passes `--allow-public-osv`. A private mirror uses `--osv-url`. Local findings do not create an OSV client.

Library helpers perform the same public-endpoint check when they can identify the client's effective URL.

Fetching a GitHub SBOM is a separate choice. `--github-repo` permits that input request, but it does not permit a later public OSV query. This is also why `--github-repo` and `--offline` conflict.

## Rendering boundary

`VexRenderer` separates generation from a serialization format. Its component-and-finding signature remains available to custom renderers. The `generate_vex_from_*` helpers use `CycloneDxJsonRenderer` unless a caller supplies another renderer.

The built-in renderers also implement `VexDocumentRenderer`. Their compatibility method creates the atomic document, then delegates to the document renderer.

`vexcalibur.vex` renders CycloneDX 1.6 JSON. `vexcalibur.openvex` renders
OpenVEX 0.2.0 JSON. `vexcalibur.csaf` renders CSAF 2.0 JSON with the VEX
profile. Each renderer owns grouping, required metadata, validation, and state
mapping.

OSV says that a vulnerability matches a package version; it does not decide exploitability for a particular deployment. OSV findings therefore enter VEX as `in_triage`. A local finding can carry a reviewed state such as `not_affected` or `exploitable`.

The atomic document boundary is where another output format can fit. A new format still needs an explicit semantic mapping. Similar field names do not guarantee that states, products, provenance, or timestamps mean the same thing.

Format conversion should expose any loss or default instead of hiding it in serialization code.

OpenVEX demonstrates this rule. It collapses `false_positive` into
`not_affected` and records the original state in notes. It emits `resolved` as
`fixed` only when `fixed_version` matches the identified product.

CSAF makes a different set of tradeoffs. It collapses `false_positive` and
`not_affected` into `known_not_affected`, then preserves the narrower state and
applicable product IDs in notes. An `exploitable` assertion needs both action
text and a machine-readable remediation category before it can become
`known_affected`. A not-affected assertion needs an impact statement. The
renderer places that evidence in product-scoped remediation and threat
objects.

The OpenVEX renderer requires explicit action and impact statements for the
states that need them. It also rejects nonidentical assertions for one
vulnerability and product. CSAF can group same-status provenance and evidence,
but rejects contradictory effective statuses for that pair.

Source `modified` timestamps describe upstream records. The OpenVEX renderer
does not claim they are statement revision times. CSAF likewise keeps them in
vulnerability notes rather than document tracking dates. The CycloneDX
renderer can place them in vulnerability `updated` because that field describes
the vulnerability record.

## Legacy command boundary

The `vexy` executable maps a small legacy command surface to the same loaders, sources, and renderer. It does not parse legacy credentials or revive OSS Index. Keeping the adapter thin preserves Vexcalibur's source validation and public-service policy.

See the [provider contract](../reference/provider-contract.md) for source
extension rules. Read the [CycloneDX](../reference/cyclonedx-vex-output.md),
[OpenVEX](../reference/openvex-output.md), and
[CSAF](../reference/csaf-output.md) references for renderer contracts.
