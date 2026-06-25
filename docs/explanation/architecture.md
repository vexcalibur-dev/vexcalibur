# Architecture

Vexcalibur separates package inventory parsing, vulnerability source access, provider-neutral finding data, and VEX rendering.

## Current Flow

1. `vexcalibur generate` accepts a CycloneDX JSON SBOM path.
2. `vexcalibur.sbom` validates the raw JSON shape, parses it with `cyclonedx-python-lib`, and extracts component identities with package URLs.
3. The selected `VulnerabilitySource` produces provider-neutral `VulnerabilityFinding` objects:
   - `vexcalibur.sources.osv.OsvSource` converts versioned component identities into OSV package queries, then maps OSV responses into findings.
   - `vexcalibur.sources.local.LocalFindingsSource` reads local findings JSON and maps each finding to a component by `bom-ref` or unique package URL.
4. `vexcalibur.vex` renders deterministic CycloneDX 1.6 VEX JSON.

## Trust Boundary

SBOMs can disclose internal package names, versions, ecosystem choices, and dependency graph details. Vexcalibur therefore treats public vulnerability services as an explicit trust boundary.

Commands that would send package URLs or SBOM-derived inventories to `https://api.osv.dev` fail unless the caller passes `--allow-public-osv`. Private mirrors use `--osv-url`. Offline workflows use `--findings-file` and do not construct an OSV client.

The same policy applies to library callers that inject an `OsvClient`: Vexcalibur checks the client's effective base URL when it is knowable and rejects public OSV unless the caller opted in.

## Source Providers

Provider-specific code belongs under `vexcalibur.sources`. Provider clients should handle source-specific request formats, response validation, pagination, and policy checks. Source adapters implement the provider-neutral `VulnerabilitySource` protocol from `vexcalibur.domain` and return shared `VulnerabilityFinding` objects. Workflow modules should orchestrate providers through that protocol rather than duplicating provider parsing or source policy.

OSV is the first network provider because it has a maintained public API and can also be mirrored internally. Local findings are the first offline provider. The architecture should leave room for additional sources without making Vexcalibur Python-specific or OSV-specific.

## VEX Rendering

The current renderer emits CycloneDX 1.6 JSON. It groups findings by vulnerability ID, source, analysis state, and analysis detail, then references affected components by `bom-ref`.

Findings are marked `in_triage` by default. That default means "detected by a source and awaiting manual exploitability analysis"; it does not claim that a component is exploitable.

## Compatibility

The package installs a `vexy` executable name for future compatibility work. The current compatibility command is only a placeholder. Existing `vexy` flag and output compatibility should be added after the core SBOM ingest, provider, VEX generation, and GitHub Action interfaces are stronger.
