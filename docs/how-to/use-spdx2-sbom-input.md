# Use an SPDX 2.3 SBOM as input

Pass a local SPDX 2.3 JSON file to `vexcalibur generate` to use its package
inventory. Vexcalibur detects the format from `spdxVersion`; the filename
extension doesn't matter.

## Before you begin

- [Install Vexcalibur](../install.md). Check `vexcalibur generate --help`:
  the input description must include SPDX 2.3 JSON.
- Have your SBOM and a reviewed [local findings file](../reference/local-findings.md)
  ready. The example names them `sbom.spdx2.json` and `findings.json`.
- Use a Bash-compatible shell and a writable output directory.

This workflow reads local files without contacting GitHub or a vulnerability
service. Installing Vexcalibur still requires access to a package index.

## Generate the document

Replace the input paths below with your files. The command replaces an existing
output file, so choose a new output path if you need to keep it.

<!-- spdx2-input-example:start -->
```bash
vexcalibur generate sbom.spdx2.json \
  --offline \
  --findings-file findings.json \
  --output vex.json
```
<!-- spdx2-input-example:end -->

Success exits with status `0`, prints nothing, and writes CycloneDX VEX to
`vex.json`. Check the result:

```bash
python -m json.tool vex.json
```

The document's `bomFormat` is `CycloneDX`. Packages without matched findings
do not appear in that output; their absence is not a `not_affected` assertion.
To select another output, follow the [generation guides](../index.md).

## Match findings to packages

The input must be a bare JSON document with `"spdxVersion": "SPDX-2.3"` and a
`packages` array, not a GitHub API response wrapped in `sbom`. For each package,
Vexcalibur reads:

| Field | Use |
| --- | --- |
| `externalRefs` | A `PACKAGE-MANAGER` reference with `referenceType: purl` supplies its package URL through `referenceLocator`. |
| `SPDXID` | Component reference for findings matching. Missing or blank values fall back to the canonical package URL. |
| `name` | Component name. The package URL name is the fallback. |
| `versionInfo` | Version for an unversioned package URL. When both carry versions, their decoded values must match. |

A finding's `component_ref` matches the package's `SPDXID` after surrounding
whitespace is removed. A finding can instead use `purl` when exactly one
inventory component has that package URL.

Packages without package URLs are omitted. Equivalent package URL references
within one package collapse; distinct package URLs are rejected. Duplicate
returned component references are also rejected. A local file keeps repository
packages with package URLs, unlike the GitHub input adapter.

This is inventory extraction, not full SPDX validation. Relationships,
licenses, and checksums do not become VEX assertions. Vexcalibur does not fetch
external documents or derive findings from SPDX annotations.

## Resolve input errors

- `unsupported spdxVersion`: use SPDX 2.3 JSON. Other SPDX 2 versions and
  tag-value, YAML, and RDF serializations are not supported.
- `conflicting SBOM format markers`: remove the conflicting format marker
  by correcting the export. Don't combine CycloneDX, SPDX 2, and SPDX 3 documents.
- `multiple distinct package URL references`: correct the package so it
  identifies one package URL.
- `conflicting version identity`: correct `versionInfo` or the package URL;
  they must describe the same version.

Input is limited to 10 MiB and 10,000 packages, including packages without
package URLs. Invalid UTF-8, duplicate JSON keys, and excessive nesting fail
before extraction. See the [CLI reference](../reference/cli.md)
for the shared input limits.

Python callers can use `vexcalibur.api.load_sbom(path)` for automatic selection
or `load_spdx2_sbom(path)` for SPDX 2.3 specifically. Execution reports use the
existing `sbom_file` inventory category. See the
[Python API reference](../reference/python-api.rst).
