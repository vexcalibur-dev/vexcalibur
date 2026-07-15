# Generate OpenVEX

Use `vexcalibur generate --format openvex` to write OpenVEX 0.2.0 JSON. CycloneDX remains the default when `--format` is absent.

**Unreleased source feature:** This guide applies to the current source tree. Published version 0.1.1 does not include `--format openvex`. OpenVEX will enter the published package in the next release.

OpenVEX requires a document author and at least one statement. Some statuses also require explicit evidence fields.

## Prerequisites

Before you begin:

- Install Git, Python 3.10 or newer, and the `uv` version in `.tool-versions`.
- Clone this repository at a revision that contains the OpenVEX implementation.
- Open a Bash-compatible shell in the repository root.
- Confirm that `/tmp` is writable, or replace the example output path.

The offline example needs no service credentials. Dependency installation may contact your configured Python package index.

## Generate from local inputs

Install the locked dependencies from the repository root:

```bash
uv sync --frozen
```

The example below reads committed fixtures. It does not contact GitHub or an OSV service.

<!-- openvex-local-example:start -->
```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --format openvex \
  --author "Example Security Team" \
  --author-role "VEX document producer" \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-openvex.json
```
<!-- openvex-local-example:end -->

The command should exit with status `0` and print nothing. It writes five statements to `/tmp/vexcalibur-openvex.json`.

## Validate the result

Validate the output against the pinned official schema used by the test suite:

```bash
uv run --frozen python - <<'PY'
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

document = json.loads(Path("/tmp/vexcalibur-openvex.json").read_text())
schema = json.loads(
    Path("tests/fixtures/schemas/openvex-0.2.0.schema.json").read_text()
)
Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)

assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
assert document["author"] == "Example Security Team"
assert len(document["statements"]) == 5
print("validated OpenVEX 0.2.0")
PY
```

You should see `validated OpenVEX 0.2.0`.

## Supply affected actions

Set `action_statement` when a local finding uses `analysis_state: exploitable`:

```json
{
  "id": "CVE-2026-0002",
  "component_ref": "pkg:npm/minimist@0.0.8",
  "analysis_state": "exploitable",
  "analysis_detail": "The affected feature is reachable.",
  "action_statement": "Upgrade minimist to version 1.2.8 or later."
}
```

Vexcalibur maps `exploitable` to OpenVEX `affected`. It refuses to use `analysis_detail` as the action because reachability analysis is not remediation guidance.

## Supply status evidence

OpenVEX rendering applies these field rules:

| Analysis state | OpenVEX status | Required field | Rule |
| --- | --- | --- | --- |
| `resolved` | `fixed` | `fixed_version` | Must equal the version in the emitted product package URL. |
| `exploitable` | `affected` | `action_statement` | Must describe remediation or mitigation. |
| `in_triage` | `under_investigation` | None | Do not supply an OpenVEX-only evidence field. |
| `false_positive` | `not_affected` | `impact_statement` | Must explain why the product is not affected. |
| `not_affected` | `not_affected` | `impact_statement` | Must explain why the product is not affected. |

Each evidence field is valid only for the states shown in the table. Vexcalibur does not substitute `analysis_detail` for one of these fields.

For a resolved finding on `pkg:pypi/django@1.2`, use the exact product version:

```json
{
  "id": "CVE-2026-0001",
  "component_ref": "component:django",
  "analysis_state": "resolved",
  "analysis_detail": "The installed release contains the fix.",
  "fixed_version": "1.2"
}
```

For a non-affected finding, state the deployment-specific impact:

```json
{
  "id": "CVE-2026-0005",
  "component_ref": "component:django",
  "analysis_state": "not_affected",
  "analysis_detail": "The affected configuration is disabled.",
  "impact_statement": "The deployment does not enable the affected configuration."
}
```

## Change the inventory or finding source

OpenVEX uses the same inventory and finding sources as CycloneDX output. Keep the format and author options, then choose one source mode:

| Task | Replace the local source options with |
| --- | --- |
| Query a private OSV-compatible service | `--osv-url https://osv.internal.example` |
| Query public OSV with approved inventory | `--allow-public-osv` |
| Fetch a GitHub SBOM | Replace the input path with `--github-repo OWNER/REPO`; keep a finding-source option |

OSV findings enter the domain as `in_triage`. They become OpenVEX `under_investigation` statements.

> **Warning:** `--allow-public-osv` sends package URLs and versions to `https://api.osv.dev`. The OpenVEX author options do not change this data-sharing boundary.

See the [CycloneDX generation guide](generate-cyclonedx-vex.md) for private mirror and GitHub authentication examples. The source flags behave the same for both output formats.

## Resolve common failures

`--author is required with --format openvex` means the command cannot identify who makes the statements. Pass an individual or organization that accepts responsibility for the document.

`OpenVEX output requires at least one vulnerability finding` means the selected source returned no findings. OpenVEX has no standalone empty-document form, so Vexcalibur does not invent a placeholder statement.

`requires an action_statement` means an `exploitable` local finding lacks remediation or mitigation text. Add that field or correct the analysis state.

`requires an impact_statement` means a `false_positive` or `not_affected` finding lacks an explicit impact. Add the field or correct the analysis state.

`requires fixed_version` means a `resolved` finding does not confirm the fixed product version. Set it to the exact version in the emitted product package URL.

`fixed_version ... does not match product` means the declared fixed version differs from the emitted product. Correct the inventory or the finding instead of weakening the assertion.

`must include a version` means the matched component has no version in its package URL or inventory field. Add a precise component version before making an OpenVEX assertion.

`overlapping assertions` means the input makes different claims about one vulnerability and product. Keep one assertion for that pair. Differences in source, state, detail, evidence, or modification time make assertions distinct.

Read the [OpenVEX output reference](../reference/openvex-output.md) before publishing or converting the result.
