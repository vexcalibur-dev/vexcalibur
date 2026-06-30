# Use A Private OSV Mirror

Use a private OSV-compatible endpoint when your SBOM includes package names,
versions, or dependency inventory that should not be sent to the public OSV
service.

## Prerequisites

- A CycloneDX JSON or XML SBOM supported by Vexcalibur.
- An internal endpoint that implements the OSV `/v1/querybatch` response shape.
- Network access from the runner to that endpoint.

## Generate VEX With The Mirror

Pass the mirror base URL with `--osv-url`:

```bash
poetry run vexcalibur generate \
  path/to/private-sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

Do not pass `--allow-public-osv` for private inventories. That flag is only for
workflows where sending package URLs and versions to `https://api.osv.dev` is
explicitly approved.

Expected success signal: the command exits with status `0` and writes
CycloneDX 1.6 VEX JSON to `/tmp/vexcalibur-vex.json`.

## Query A Package URL With The Mirror

Use the same `--osv-url` option for direct package URL checks:

```bash
poetry run vexcalibur query-osv \
  pkg:pypi/example@1.0.0 \
  --osv-url https://osv.internal.example
```

Expected success signal: the command exits with status `0` and prints one line
for the submitted package URL.

## Failure Modes

Vexcalibur treats OSV-compatible providers as source systems, not as trusted
local data. It fails the command when the mirror returns invalid JSON, a
non-object response, a mismatched batch response shape, repeated pagination
tokens, or too many pages.

If a private mirror is unavailable, either fix the mirror before generating VEX
or use [local findings](../reference/local-findings.md) with `--offline`.
