# No-Network Local Findings Tutorial

This tutorial generates CycloneDX 1.6 VEX JSON from committed fixture files
without contacting OSV or any other vulnerability service.

Use this path when you are evaluating Vexcalibur from a private environment, or
when another trusted process already produced vulnerability and exploitability
findings.

## Prerequisites

- Python 3.10 or newer
- uv 0.11.17
- Dependency installation access through PyPI, an internal package index, a
  populated uv cache, or a prebuilt environment.

Install the project and development dependencies from the repository root:

```bash
uv sync
```

After dependencies are installed, the generation command in this tutorial does
not contact OSV or any other vulnerability service.

Confirm that the CLI starts:

```bash
uv run --frozen vexcalibur --help
```

## Generate VEX Offline

Run `generate` with the fixture SBOM and fixture findings file:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-offline-vex.json
```

Expected success signal: the command exits with status `0` and writes
`/tmp/vexcalibur-offline-vex.json`.

## Verify The Output

Inspect the generated document:

```bash
python -m json.tool /tmp/vexcalibur-offline-vex.json | sed -n '1,120p'
```

Verify stable fields and the expected fixture vulnerability count:

```bash
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-offline-vex.json").read_text())
assert vex["bomFormat"] == "CycloneDX"
assert vex["specVersion"] == "1.6"
assert vex["metadata"]["timestamp"] == "2026-06-23T00:00:00+00:00"
assert len(vex["vulnerabilities"]) == 5
print("generated offline CycloneDX VEX")
PY
```

Expected success signal: the Python verification command prints
`generated offline CycloneDX VEX`.

## What The Command Did

`--offline --findings-file` selects the local findings source. Vexcalibur parses
the SBOM locally, matches each finding to an SBOM component by `component_ref` or
unique package URL, and renders CycloneDX VEX. It does not construct an OSV
client or send package data to a network provider.

Use the [local findings reference](../reference/local-findings.md) when writing
your own findings file.
