# Write and use a local findings file

The quickstart used a ready-made findings file. In this tutorial, we'll write one finding. We'll use it to generate VEX and confirm that our analysis reached the output.

## Set up the project

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

Dependency installation may contact your configured package index. The later generation step uses only the local SBOM and findings file.

We'll reuse `tests/fixtures/sbom/cyclonedx-json-simple.json`. Its Django component has the reference `component:django`.

## Describe the finding

Create `/tmp/vexcalibur-findings.json`:

```bash
cat >/tmp/vexcalibur-findings.json <<'JSON'
{
  "findings": [
    {
      "id": "CVE-2026-0001",
      "component_ref": "component:django",
      "source_name": "Internal Review",
      "source_url": "https://security.example.test/reviews/CVE-2026-0001",
      "modified": "2026-07-01T12:00:00Z",
      "analysis_state": "not_affected",
      "analysis_detail": "The application does not enable the affected feature."
    }
  ]
}
JSON
```

The component reference connects the finding to the SBOM. The state and detail record the result of our exploitability review.

## Generate VEX

Run the generator without a network source:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file /tmp/vexcalibur-findings.json \
  --timestamp 2026-07-01T12:00:00Z \
  --output /tmp/vexcalibur-local-vex.json
```

The command should exit without output and create `/tmp/vexcalibur-local-vex.json`.

## Check the analysis

Read the generated vulnerability entry:

```bash
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-local-vex.json").read_text())
finding = vex["vulnerabilities"][0]
assert finding["id"] == "CVE-2026-0001"
assert finding["analysis"]["state"] == "not_affected"
assert finding["analysis"]["detail"] == (
    "The application does not enable the affected feature."
)
assert finding["affects"][0]["ref"] == "component:django"
print("preserved local exploitability analysis")
PY
```

You should see `preserved local exploitability analysis`.

Vexcalibur validated the local JSON. It matched `component:django`. It copied the review state into CycloneDX VEX. It did not create an OSV client.

Use the [local findings reference](../reference/local-findings.md) for every field, default, size limit, and matching rule.
