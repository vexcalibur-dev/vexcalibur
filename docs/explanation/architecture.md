# Architecture and trust boundaries

Vexcalibur separates package inventory, source access, normalized findings, and VEX rendering. Provider rules stay out of the output writer. Format rules stay out of network clients.

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
              CycloneDX 1.6 renderer
                         |
                         v
                  VEX JSON document
```

The two inventory paths meet at `ComponentIdentity`. The two finding paths meet at `VulnerabilityFinding`. The renderer receives the same value types from every path.

## Inventory boundary

`vexcalibur.sbom` handles local CycloneDX JSON and XML. It applies file-size, nesting, component-count, package URL, duplicate-reference, and XML hardening checks before it returns components.

`vexcalibur.github_sbom` handles GitHub's asynchronous Dependency Graph API. It requests the SPDX 2.3 JSON report and waits for the download. It then validates the response and extracts package URL references. Both loaders produce the same component shape.

Components without package URLs do not cross this boundary. Source adapters need package identity, and a VEX `affects` entry needs a stable component reference.

## Finding-source boundary

A `VulnerabilitySource` receives all normalized components and returns `VulnerabilityFinding` values.

`OsvSource` builds version-specific OSV queries and maps matches to findings. `LocalFindingsSource` validates a JSON file. It matches each item by component reference or unique package URL.

Provider-specific request and parsing logic stays inside the adapter.

`VulnerabilitySourceInputError` means the inventory cannot form valid provider input. Other source failures inherit from `VulnerabilitySourceError`, with provider-specific subclasses for useful error categories.

## Network boundary

An SBOM can expose internal package names, exact versions, and dependency choices. Vexcalibur does not treat a vulnerability lookup as harmless metadata access.

Public OSV fails closed until the caller passes `--allow-public-osv`. A private mirror uses `--osv-url`. Local findings do not create an OSV client.

Library helpers perform the same public-endpoint check when they can identify the client's effective URL.

Fetching a GitHub SBOM is a separate choice. `--github-repo` permits that input request, but it does not permit a later public OSV query. This is also why `--github-repo` and `--offline` conflict.

## Rendering boundary

`vexcalibur.vex` is currently a CycloneDX 1.6 JSON renderer. It groups findings by vulnerability, source, state, and detail. Each group points at the component references it assesses.

OSV says that a vulnerability matches a package version; it does not decide exploitability for a particular deployment. OSV findings therefore enter VEX as `in_triage`. A local finding can carry a reviewed state such as `not_affected` or `exploitable`.

The normalized finding boundary is also where another VEX renderer can fit. A new format still needs an explicit semantic mapping. Similar field names do not guarantee that states, products, provenance, or timestamps mean the same thing.

Format conversion should expose any loss or default instead of hiding it in serialization code.

## Legacy command boundary

The `vexy` executable maps a small legacy command surface to the same loaders, sources, and renderer. It does not parse legacy credentials or revive OSS Index. Keeping the adapter thin preserves Vexcalibur's source validation and public-service policy.

See the [provider contract](../reference/provider-contract.md) for extension rules and the [output reference](../reference/cyclonedx-vex-output.md) for the current rendering contract.
