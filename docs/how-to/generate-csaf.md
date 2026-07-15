# Generate CSAF VEX

Use `vexcalibur generate --format csaf` to write a CSAF 2.0 JSON document with
the `csaf_vex` profile. CycloneDX remains the default when `--format` is absent.

CSAF identifies the organization responsible for a document. Before you run
the command, choose a tracking ID and title, confirm the publisher name and
category, and use an absolute namespace URL controlled by that publisher.

## Prerequisites

Before you begin:

- Install Git, Python 3.10 or newer, and the `uv` version in `.tool-versions`.
- Clone this repository at version 0.3.0 or later.
- Open a Bash-compatible shell in the repository root.
- Confirm that `/tmp` is writable, or replace the example output path.

The offline example needs no service credentials. Dependency installation may
contact your configured Python package index.

## Generate from local inputs

Install the locked dependencies from the repository root:

```bash
uv sync --frozen
```

The example below reads committed fixtures. It does not contact GitHub or an
OSV service.

<!-- csaf-local-example:start -->
```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --format csaf \
  --csaf-version 2.0 \
  --csaf-document-id ACME-VEX-2026-001 \
  --csaf-document-title "ACME component exploitability assessment" \
  --csaf-publisher-name "ACME Product Security" \
  --csaf-publisher-namespace https://security.example.test \
  --csaf-publisher-category vendor \
  --csaf-document-status final \
  --timestamp 2026-07-15T00:00:00Z \
  --output /tmp/acme-vex-2026-001.json
```
<!-- csaf-local-example:end -->

The command should exit with status `0` and print nothing. It writes five
vulnerability entries covering two versioned products.

The output basename is not arbitrary. Vexcalibur derives it from the tracking
ID according to the CSAF filename rule. `ACME-VEX-2026-001` therefore requires
`acme-vex-2026-001.json`.

## Inspect the result

Check the profile, publisher claim, first revision, products, and vulnerability
count:

```bash
uv run --frozen python - <<'PY'
import json
from pathlib import Path

document = json.loads(Path("/tmp/acme-vex-2026-001.json").read_text())
metadata = document["document"]

assert metadata["category"] == "csaf_vex"
assert metadata["csaf_version"] == "2.0"
assert metadata["publisher"]["name"] == "ACME Product Security"
assert metadata["tracking"]["id"] == "ACME-VEX-2026-001"
assert metadata["tracking"]["version"] == "1"
assert metadata["tracking"]["revision_history"][0]["number"] == "1"
assert len(document["product_tree"]["full_product_names"]) == 2
assert len(document["vulnerabilities"]) == 5
print("generated CSAF 2.0 VEX")
PY
```

You should see `generated CSAF 2.0 VEX`.

Repository tests run the generated contract through the pinned OASIS schema
and the complete mandatory-test suite. See the [CSAF output
reference](../reference/csaf-output.md) for the exact pins and the limits of
schema-only validation.

## Choose document metadata

Every CSAF document needs an identity and publisher claim:

| Option | What to supply |
| --- | --- |
| `--csaf-document-id` | A stable tracking ID chosen by the publisher; line terminators are rejected. |
| `--csaf-document-title` | A human-readable title for this assessment. |
| `--csaf-publisher-name` | The organization responsible for the document. |
| `--csaf-publisher-namespace` | A normalized absolute HTTP(S) URL controlled by that publisher. |
| `--csaf-publisher-category` | `coordinator`, `discoverer`, `other`, `user`, or `vendor`. |
| `--csaf-document-status` | `draft`, `final`, or `interim`; defaults to `draft`. |

Vexcalibur does not accept `translator` as a publisher category. The command
produces a new assessment; it does not translate an existing CSAF document.

Use ASCII RFC 3986 syntax for the publisher namespace. Write internationalized
hosts in IDNA form and percent-encode non-ASCII path characters.

The first generated document always has tracking version `1` and one revision
history entry numbered `1` with summary `Initial version.`. The selected
timestamp supplies the initial release, current release, first revision, and
generator dates. Vexcalibur does not create later revisions in this increment.

## Supply CSAF evidence

CSAF's VEX profile requires structured evidence for affected and unaffected
products. Put that evidence in the local finding instead of asking the
renderer to infer it from `analysis_detail`.

| Analysis state | CSAF product status | Required fields |
| --- | --- | --- |
| `resolved` | `fixed` | `fixed_version`, equal to the emitted product version |
| `exploitable` | `known_affected` | `action_statement` and `remediation_category` |
| `in_triage` | `under_investigation` | None |
| `false_positive` | `known_not_affected` | `impact_statement` |
| `not_affected` | `known_not_affected` | `impact_statement` |

For an exploitable product, provide both the action and its machine-readable
kind:

```json
{
  "id": "CVE-2026-0002",
  "component_ref": "pkg:npm/minimist@0.0.8",
  "analysis_state": "exploitable",
  "analysis_detail": "The affected feature is reachable.",
  "action_statement": "Upgrade minimist to version 1.2.8 or later.",
  "remediation_category": "vendor_fix"
}
```

Accepted remediation categories are `mitigation`, `no_fix_planned`,
`none_available`, `vendor_fix`, and `workaround`.

For an unaffected product, explain the impact explicitly:

```json
{
  "id": "CVE-2026-0005",
  "component_ref": "component:django",
  "analysis_state": "not_affected",
  "analysis_detail": "The affected configuration is disabled.",
  "impact_statement": "The deployment does not enable the affected configuration."
}
```

Both `false_positive` and `not_affected` become CSAF `known_not_affected`.
That mapping loses status precision, so Vexcalibur records the original state
in the vulnerability notes.

## Change the inventory or finding source

CSAF uses the same inventory and finding sources as the other output formats.
Keep the CSAF metadata options, then choose one source mode:

| Task | Change the offline example this way |
| --- | --- |
| Query a private OSV-compatible service | Remove `--offline --findings-file ...`; add `--osv-url https://osv.internal.example`. |
| Query public OSV with approved inventory | Remove `--offline --findings-file ...`; add `--allow-public-osv`. |
| Fetch a GitHub SBOM and keep local findings | Remove the input path and `--offline`; add `--github-repo OWNER/REPO` and retain `--findings-file ...`. |

OSV findings enter the domain as `in_triage`. They become CSAF
`under_investigation` entries.

> **Warning:** `--allow-public-osv` sends package URLs and versions to
> `https://api.osv.dev`. CSAF publisher metadata does not change this
> data-sharing boundary.

See the [CycloneDX generation guide](generate-cyclonedx-vex.md) for private
mirror and GitHub authentication examples.

## Name a file from its tracking ID

When `--output` writes a file, derive its basename this way:

1. Lowercase the document tracking ID.
2. Replace each run matching `[^+\-a-z0-9]+` with one underscore. Existing
   underscores are replaced and adjacent ones collapse.
3. Append `.json`.

For example, `ACME VEX:2026/001` becomes `acme_vex_2026_001.json`. An output
path with another basename is rejected. Standard output has no filename, so
the filename rule does not apply when `--output` is absent.

## Resolve common failures

`... required with --format csaf` means one or more document or publisher
options are missing. Supply all five required values. A `must not be empty`
error means a supplied value contains no usable text.

`requires an action_statement` or `requires remediation_category` means an
`exploitable` finding lacks structured remediation evidence. Add both fields
or correct the analysis state.

`requires an impact_statement` means a `false_positive` or `not_affected`
finding lacks an explicit impact. Add the field or correct the state.

`requires fixed_version` means a `resolved` finding does not confirm the fixed
product version. Set it to the exact version in the emitted product package
URL.

`must include a version` means the matched component has no version in its
package URL or inventory field. Add a precise component version before making
a CSAF assertion.

An output-filename error means the basename does not match the tracking ID.
Apply the filename steps above; changing directories does not affect the
required basename.

A contradictory-status error means the input gives one vulnerability and
product more than one effective CSAF product status. Correct the assessment so
the pair has one status. Multiple same-status records may preserve distinct
provenance or evidence and are grouped.

The command writes a local JSON document. It does not read CSAF, convert an
existing VEX document, create a trusted-provider feed, sign the result, add
distribution or TLP policy, publish it, or revise an earlier document.
