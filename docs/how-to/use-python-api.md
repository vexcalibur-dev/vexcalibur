# Generate VEX from Python

Use `vexcalibur.api` when an application needs VEX generation without invoking the command-line interface. This example stays offline: it reads a CycloneDX SBOM and reviewed findings from the Vexcalibur test fixtures.

## Prepare the checkout

Run the example from a Vexcalibur source checkout. Install the locked project environment first:

```bash
uv sync --frozen
```

The example uses only the supported facade. It catches the documented input, source, and rendering errors before it writes output.

```{literalinclude} ../examples/use_python_api.py
:language: python
:linenos:
```

## Generate and verify the document

Run the checked-in example:

```bash
uv run --frozen python docs/examples/use_python_api.py
```

A successful run prints:

```text
Wrote 5 findings to build/vexcalibur-python-api.json
```

Confirm that the output is CycloneDX 1.6 JSON with five vulnerability entries:

```bash
uv run --frozen python - <<'PY'
import json
from pathlib import Path

document = json.loads(
    Path("build/vexcalibur-python-api.json").read_text(encoding="utf-8")
)
assert document["bomFormat"] == "CycloneDX"
assert document["specVersion"] == "1.6"
assert len(document["vulnerabilities"]) == 5
print("CycloneDX 1.6 VEX contains 5 findings")
PY
```

Use application paths in place of the two fixture paths. Keep imports under `vexcalibur.api`; implementation modules can change outside the 1.x compatibility contract.

To query an OSV-compatible service instead of reviewed local findings, use `generate_vex_from_sbom`. Public OSV remains blocked until the call includes `allow_public_osv=True`. See [Use a private OSV mirror](use-private-osv-mirror.md) before sending a private inventory to any service.

When the embedding also needs counts and a digest for the exact rendered bytes,
follow [Generate an execution report from Python](generate-execution-report-from-python.md).
