# Quickstart

This tutorial generates CycloneDX 1.6 VEX JSON from the public fixture SBOM included in the repository.

The example intentionally calls the public OSV API. Use it only with the fixture SBOM or another package inventory you are allowed to send to a public service. For private SBOMs, use a private OSV mirror with `--osv-url` instead.

## Prerequisites

- Python 3.10 or newer
- Poetry 2.x

Install the project and development dependencies from the repository root:

```bash
poetry install
```

Confirm that the CLI starts:

```bash
poetry run vexcalibur --help
```

## Generate VEX

Run `generate` against the fixture SBOM. The `--allow-public-osv` flag is required because this command sends fixture package URLs and versions to `https://api.osv.dev`.

This step requires internet access. OSV data can change, so the number of vulnerability entries can vary over time.

```bash
poetry run vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

Inspect the generated document:

```bash
python -m json.tool /tmp/vexcalibur-vex.json | sed -n '1,80p'
```

Verify the stable document metadata:

```bash
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-vex.json").read_text())
assert vex["bomFormat"] == "CycloneDX"
assert vex["specVersion"] == "1.6"
assert vex["metadata"]["timestamp"] == "2026-06-23T00:00:00+00:00"
print("generated CycloneDX VEX")
PY
```

The output is a CycloneDX 1.6 document with VEX vulnerability entries for OSV matches. OSV-derived findings are currently marked `in_triage` because Vexcalibur has not yet implemented policy-driven VEX state selection for OSV results.

## Use A Private OSV Mirror

For private SBOMs or sensitive inventories, omit `--allow-public-osv` and point Vexcalibur at an internal OSV-compatible endpoint:

```bash
poetry run vexcalibur generate \
  path/to/private-sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

Replace `https://osv.internal.example` with your mirror URL. Vexcalibur treats that URL as the source of OSV-compatible query responses.

## Next Steps

- Use [Generate CycloneDX VEX](../how-to/generate-cyclonedx-vex.md) for command recipes.
- Use the [CLI reference](../reference/cli.md) for current flags and behavior.
- Read [Architecture](../explanation/architecture.md) before changing provider behavior or public-service policy.
