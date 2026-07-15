# Generate your first VEX document

In this tutorial, we'll turn two committed example files into CycloneDX 1.6 VEX JSON. The generation step uses only local inputs, so no package inventory leaves the repository.

## Set up Vexcalibur

You need:

- Git.
- Python 3.10 or newer.
- `uv` 0.11.17.
- A POSIX-style shell.

Clone the source and enter its root:

```bash
git clone https://github.com/vexcalibur-dev/vexcalibur.git
cd vexcalibur
```

Install the locked dependencies:

```bash
uv sync
```

This setup step may contact your configured package index. Once the dependencies are installed, the rest of the tutorial does not need a network finding source.

Check that the command starts:

```bash
uv run --frozen vexcalibur --help
```

You should see the `query-osv` and `generate` commands.

## Generate the document

Run Vexcalibur with the example SBOM and findings file:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

The command should exit without output and create `/tmp/vexcalibur-vex.json`.

## Inspect the result

Print the first part of the document:

```bash
python -m json.tool /tmp/vexcalibur-vex.json | sed -n '1,80p'
```

Now check the fields this tutorial expects:

```bash
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-vex.json").read_text())
assert vex["bomFormat"] == "CycloneDX"
assert vex["specVersion"] == "1.6"
assert vex["metadata"]["timestamp"] == "2026-06-23T00:00:00+00:00"
assert len(vex["vulnerabilities"]) == 5
print("generated offline CycloneDX VEX")
PY
```

You should see `generated offline CycloneDX VEX`.

Vexcalibur read component identities from the SBOM. It matched the local findings to those components, then rendered the result. `--offline` prevented network finding sources. The fixed timestamp made the metadata and generated identifiers stable.

## Keep going

Next, [write your own local findings file](offline-local-findings.md). When you need a network source, use the [generation how-to](../how-to/generate-cyclonedx-vex.md) and choose either a private OSV mirror or an explicitly approved public OSV query.
