# Use A Private OSV Mirror

Use a private OSV-compatible endpoint when your SBOM includes package names,
versions, or dependency inventory that should not be sent to the public OSV
service.

## Prerequisites

- A local CycloneDX JSON/XML SBOM supported by Vexcalibur, or a GitHub
  repository whose Dependency Graph SBOM should be used as the package
  inventory.
- An internal endpoint that implements the OSV `/v1/querybatch` response shape.
- Network access from the runner to that endpoint.

## Generate VEX With The Mirror

Pass the mirror base URL with `--osv-url`:

```bash
uv run --frozen vexcalibur generate \
  path/to/private-sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

Do not pass `--allow-public-osv` for private inventories. That flag is only for
workflows where sending package URLs and versions to `https://api.osv.dev` is
explicitly approved.

Private mirror URLs must be absolute `https://` URLs with a hostname. Cleartext
`http://` is accepted only for loopback hosts such as `http://127.0.0.1:8080`
when testing a local OSV-compatible service.

Expected success signal: the command exits with status `0` and writes
CycloneDX 1.6 VEX JSON to `/tmp/vexcalibur-vex.json`.

Use the same mirror when the package inventory comes from GitHub Dependency
Graph:

```bash
uv run --frozen vexcalibur generate \
  --github-repo internal/example \
  --github-token-env GH_ENTERPRISE_TOKEN \
  --github-api-url https://github.example.test/api/v3 \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

Fetching the SBOM from GitHub is separate from querying OSV. Keep using
`--osv-url` to avoid sending the GitHub-derived package inventory to public OSV.

## Query A Package URL With The Mirror

Use the same `--osv-url` option for direct package URL checks:

```bash
uv run --frozen vexcalibur query-osv \
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
