# Generate CycloneDX VEX

Use `vexcalibur generate` when you have a supported CycloneDX JSON SBOM and want CycloneDX 1.6 VEX JSON based on OSV-compatible vulnerability findings.

## Generate From A Public Fixture

The repository fixture is safe to use in public-service examples. The command must still opt in before contacting the public OSV API:

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```

Live OSV results can change. Add `--timestamp` when tests or review steps need deterministic document metadata:

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

## Generate With A Private OSV Mirror

Use `--osv-url` for private mirrors. Do not pass `--allow-public-osv` for private SBOMs:

```bash
poetry run vexcalibur generate \
  path/to/sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

The configured endpoint must implement the OSV query API shape used by Vexcalibur's provider client.

## Generate Offline From Local Findings

Use `--findings-file` when another trusted process has already produced vulnerability findings or exploitability analysis. This mode never contacts OSV.

```bash
poetry run vexcalibur generate \
  path/to/sbom.json \
  --offline \
  --findings-file path/to/findings.json \
  --output /tmp/vexcalibur-vex.json
```

The findings file uses Vexcalibur's [local findings JSON format](../reference/local-findings.md). Local findings must identify SBOM components by `component_ref` or by a package URL that appears exactly once in the SBOM.

## Write To Standard Output

Omit `--output` to write the VEX JSON to standard output:

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv
```

## Supported Input

`generate` currently supports:

- CycloneDX JSON SBOMs with `specVersion` `1.4`, `1.5`, or `1.6`.
- Files up to 10 MiB.
- Up to 10,000 components.
- Component nesting up to 50 levels.
- Components with package URLs and versions from either the PURL or CycloneDX `version` field.
- Unique `bom-ref` values for components with package URLs.

`generate` intentionally fails when no precise query set can be built. That is safer than producing an empty VEX document that could look authoritative.

## Current Limitations

The first generator does not yet support:

- CycloneDX XML SBOM input.
- User-authored exploitability analysis details.
- Policy-driven VEX state selection.
- Existing `vexy` flags or output compatibility.
