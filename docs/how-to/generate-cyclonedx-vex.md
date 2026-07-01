# Generate CycloneDX VEX

Use `vexcalibur generate` when you have a supported CycloneDX JSON or XML SBOM and want CycloneDX 1.6 VEX JSON based on OSV-compatible vulnerability findings.

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

## Choose A Source Mode For CI

Use exactly one vulnerability source mode in automated jobs:

- Public fixture or intentionally public package inventory: use `--allow-public-osv`.
- Private SBOM with an internal OSV-compatible service: use `--osv-url https://osv.internal.example`.
- Offline or pre-reviewed vulnerability data: use `--offline --findings-file path/to/findings.json`.

Do not pass `--allow-public-osv` for private SBOMs. Do not combine `--findings-file` with `--allow-public-osv` or `--osv-url`; local findings mode is the no-network path.

## Write To Standard Output

Omit `--output` to write the VEX JSON to standard output:

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv
```

## Generate From XML Input

Use the same command for CycloneDX XML SBOM input:

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-xml-simple.xml \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```

## Supported Input

All `generate` source modes currently support:

- CycloneDX JSON SBOMs with `specVersion` `1.4`, `1.5`, or `1.6`; JSON input must be UTF-8.
- CycloneDX XML SBOMs rooted at `bom` in the `http://cyclonedx.org/schema/bom/1.4`, `/1.5`, or `/1.6` namespace; XML may use parser-detected XML encodings such as UTF-8 or UTF-16, and DTD, entity, and external-reference declarations are rejected.
- Files up to 10 MiB.
- Up to 10,000 components.
- Component nesting up to 50 levels.
- Unique `bom-ref` values for components with package URLs.

OSV-backed generation also requires components with package URLs and versions from either the PURL or CycloneDX `version` field. It intentionally fails when no precise query set can be built. That is safer than producing an empty VEX document that could look authoritative.

Local findings mode can produce an empty VEX document when the findings file explicitly contains no findings.

## Current Limitations

The current generator does not yet support:

- Policy-driven VEX state selection for OSV-derived findings.
- Legacy `vexy` XML output or CycloneDX `1.4` VEX output.

See the [CycloneDX VEX output reference](../reference/cyclonedx-vex-output.md)
for the generated document contract.
