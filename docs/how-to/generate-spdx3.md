# Generate SPDX 3 VEX

Use `vexcalibur generate --format spdx3` to write an SPDX 3.0.1 JSON-LD
document that expresses VEX through the security profile's assessment
relationships. CycloneDX remains the default when `--format` is absent.

SPDX records who created a document. Choose the person or organization that
accepts responsibility for the assessments before you run the command, and
pass that name with `--creator`.

## Prerequisites

Before you begin:

- Install Vexcalibur `v0.7.0` or newer, the first release with SPDX 3 output.
  See [Install Vexcalibur](install.md).
- Have a CycloneDX SBOM and a reviewed findings file ready. The example calls
  them `sbom.json` and `findings.json`.
- Open a Bash-compatible shell.
- Confirm that `/tmp` is writable, or replace the example output path.

This example needs no service credentials and contacts no network service.

## Generate from local inputs

Confirm that your release supports SPDX 3:

```bash
vexcalibur generate --help
```

The `--format` choices must include `spdx3`. If they don't, install a newer
release.

The command below reads only local files. It does not contact GitHub or an
OSV service.

<!-- spdx3-local-example:start -->
```bash
vexcalibur generate \
  sbom.json \
  --offline \
  --findings-file findings.json \
  --format spdx3 \
  --creator "Example Security Team" \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vex.spdx3.json
```
<!-- spdx3-local-example:end -->

The command should exit with status `0` and print nothing. It writes grouped
assessment relationships to `/tmp/vex.spdx3.json`.

Findings that agree on the vulnerability, source, state, and evidence become a
single relationship whose `to` lists every affected product, so the
relationship count can be lower than the finding count. The [SPDX 3 output
reference](../reference/spdx3-output.md) lists the exact grouping values.

## Check the result

Confirm the context and count the assessment relationships:

```bash
python - <<'PY'
import json
from pathlib import Path

document = json.loads(Path("/tmp/vex.spdx3.json").read_text())

assert document["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
relationships = [
    element
    for element in document["@graph"]
    if str(element.get("type", "")).endswith("VulnAssessmentRelationship")
]
assert relationships
print(f"SPDX 3.0.1 document with {len(relationships)} assessment relationships")
PY
```

This is a field check, not validation against the full SPDX 3 schema. The
repository test suite validates generated documents against the pinned
official 3.0.1 schema on every change; see the [SPDX 3 output
reference](../reference/spdx3-output.md) for the exact pin.

To run that schema validation yourself, install from source and use the
committed schema at `tests/fixtures/schemas/spdx-3.0.1.schema.json` with the
checkout's `jsonschema` dependency.

## Supply status evidence

SPDX rendering applies these field rules to local findings:

| Analysis state | SPDX relationship | Required field | Rule |
| --- | --- | --- | --- |
| `resolved` | `VexFixedVulnAssessmentRelationship` | `fixed_version` | Must equal the version in the emitted product package URL. |
| `exploitable` | `VexAffectedVulnAssessmentRelationship` | `action_statement` | Must describe remediation or mitigation. |
| `in_triage` | `VexUnderInvestigationVulnAssessmentRelationship` | None | Do not supply an SPDX-only evidence field. |
| `false_positive` | `VexNotAffectedVulnAssessmentRelationship` | `impact_statement` | Must explain why the product is not affected. |
| `not_affected` | `VexNotAffectedVulnAssessmentRelationship` | `impact_statement` | Must explain why the product is not affected. |

Each evidence field is valid only for the states shown in the table.
Vexcalibur does not substitute `analysis_detail` for one of these fields.

For an exploitable finding, state the remediation:

```json
{
  "id": "CVE-2026-0002",
  "component_ref": "pkg:npm/minimist@0.0.8",
  "analysis_state": "exploitable",
  "analysis_detail": "The affected feature is reachable.",
  "action_statement": "Upgrade minimist to version 1.2.8 or later."
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

SPDX output uses the same inventory and finding sources as CycloneDX output.
Keep the format and creator options, then choose one source mode:

| Task | Replace the local source options with |
| --- | --- |
| Query a private OSV-compatible service | `--osv-url https://osv.internal.example` |
| Query public OSV with approved inventory | `--allow-public-osv` |
| Fetch a GitHub SBOM | Replace the input path with `--github-repo OWNER/REPO`; keep a finding-source option |

OSV findings enter the domain as `in_triage`. They become
`VexUnderInvestigationVulnAssessmentRelationship` elements.

> **Warning:** `--allow-public-osv` sends package URLs and versions to
> `https://api.osv.dev`. The SPDX creator option does not change this
> data-sharing boundary.

See the [CycloneDX generation guide](generate-cyclonedx-vex.md) for private
mirror and GitHub authentication examples. The source flags behave the same
for every output format.

## Resolve common failures

`--creator is required with --format spdx3` means the command cannot identify
who makes the assessments. Pass an individual or organization that accepts
responsibility for the document.

`SPDX output requires at least one vulnerability finding` means the selected
source returned no findings. Vexcalibur does not invent a placeholder
assessment for an empty result.

`requires an action_statement` means an `exploitable` local finding lacks
remediation or mitigation text. Add that field or correct the analysis state.

`require an impact_statement` means a `false_positive` or `not_affected`
finding lacks an explicit impact. Add the field or correct the analysis state.

`require fixed_version` means a `resolved` finding does not confirm the fixed
product version. Set it to the exact version in the emitted product package
URL.

`fixed_version ... does not match product` means the declared fixed version
differs from the emitted product. Correct the inventory or the finding instead
of weakening the assertion.

`must include a version` means the matched component has no version in its
package URL or inventory field. Add a precise component version before making
an SPDX assertion.

`overlapping assertions` means the input makes different claims about one
vulnerability and product. Keep one assertion for that pair. Differences in
source, state, detail, evidence, remediation category, or modification time
make assertions distinct.

Read the [SPDX 3 output reference](../reference/spdx3-output.md) before
publishing or converting the result.
