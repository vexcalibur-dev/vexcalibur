# Use an SPDX 3 SBOM as input

`vexcalibur generate` reads a local SPDX 3.0.1 JSON-LD SBOM the same way it
reads a CycloneDX file. Pass the path as `INPUT_FILE`; the format comes from
the document's content, so there is no format flag to set. Finding sources and
output formats behave the same for both inputs.

## Prerequisites

Before you begin:

- Install a Vexcalibur release that lists SPDX 3 SBOM input. No release
  through `v0.7.2` includes it. See [Install Vexcalibur](../install.md).
- Have an SPDX 3.0.1 JSON-LD SBOM and a reviewed findings file ready. The
  example calls them `sbom.spdx3.json` and `findings.json`.
- Open a Bash-compatible shell.
- Confirm that `/tmp` is writable, or replace the example output path.

This example needs no service credentials and contacts no network service.

## Provide the fields Vexcalibur reads

Vexcalibur reads `software_Package` elements from the document's `@graph`,
including the derived `ai_AIPackage` and `dataset_DatasetPackage` types. The
`@context` must be the SPDX 3.0.1 JSON-LD context string.

| SPDX 3 field | Used as |
| --- | --- |
| `spdxId` | Component reference for findings matching |
| `name` | Component name; the package URL name is the fallback |
| `software_packageUrl` | Package URL |
| `externalIdentifier` entry of type `packageUrl` | Package URL |
| `software_packageVersion` | Version for an unversioned package URL |

An `externalIdentifier` entry may be the inline object or a reference to an
`ExternalIdentifier` elsewhere in `@graph`. A package may carry its package
URL in either field, or in both when the values are equivalent. Two distinct
package URLs on one package are rejected. Packages without package URLs are
omitted, because finding sources and VEX assertions need package identity.

## Generate from local inputs

Confirm that your release supports SPDX 3 input:

```bash
vexcalibur generate --help
```

The `INPUT_FILE` description must mention SPDX 3 JSON-LD. If it doesn't,
install a newer release.

The command below reads only local files. It does not contact GitHub or an
OSV service.

<!-- spdx3-input-example:start -->
```bash
vexcalibur generate \
  sbom.spdx3.json \
  --offline \
  --findings-file findings.json \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```
<!-- spdx3-input-example:end -->

The command should exit with status `0` and print nothing. It writes CycloneDX
VEX to `/tmp/vexcalibur-vex.json`; pass `--format` to select another output.

## Check the result

Confirm the output format and that an SBOM package reached the document:

```bash
python - <<'PY'
import json
from pathlib import Path

document = json.loads(Path("/tmp/vexcalibur-vex.json").read_text())

assert document["bomFormat"] == "CycloneDX"
assert document["vulnerabilities"]
print(f"CycloneDX VEX with {len(document['vulnerabilities'])} vulnerabilities")
PY
```

## Match findings to SPDX packages

A local finding names its component by `component_ref` or by `purl`. For SPDX
input, `component_ref` must equal the package's `spdxId`. When the SBOM's
identifiers are long IRIs, matching by package URL is usually easier:

```json
{
  "id": "CVE-2026-0101",
  "purl": "pkg:pypi/django@1.2",
  "analysis_state": "in_triage",
  "analysis_detail": "Impact analysis is still underway."
}
```

A `purl` match requires exactly one SBOM package with that package URL. See
the [local findings reference](../reference/local-findings.md) for the full
matching rules.

## Resolve common failures

`must declare the SPDX 3.0.1 JSON-LD context` means the document's `@context`
is missing, is not a string, or names another SPDX version. Vexcalibur pins
one context per release instead of guessing across versions.

`carries both CycloneDX and SPDX 3 format markers` means the JSON contains
both `bomFormat` and `@graph`. Fix the document instead of relying on a
guessed format.

`not a supported SBOM document` means the JSON has neither marker. Confirm the
file is a CycloneDX SBOM or an SPDX 3.0.1 JSON-LD document.

`multiple distinct package URL identities` means one package carries two
different package URLs. Keep one identity per package.

`conflicting version identity` means `software_packageVersion` contradicts the
version inside the package URL. Correct one of them; when both are present
their decoded values must match.

`must include a version` appears later, at output rendering, when a matched
package has no version in its package URL or `software_packageVersion`. Add a
precise version before making assertions about the package.

Read the [command-line reference](../reference/cli.md) for the complete input
contract.
