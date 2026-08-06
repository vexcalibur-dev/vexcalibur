# Generate CycloneDX VEX

Use `vexcalibur generate` to write CycloneDX 1.6 VEX JSON from a local CycloneDX SBOM or a GitHub Dependency Graph SBOM.

The `uv run --frozen` examples assume a Vexcalibur source checkout. Run them from its root after installing dependencies with `uv sync`. When using an installed release, run `vexcalibur` directly and substitute your own file paths.

Choose one inventory input and one finding source:

| Input | Option |
| --- | --- |
| Local CycloneDX JSON or XML | Positional `INPUT_FILE` |
| GitHub Dependency Graph SBOM | `--github-repo OWNER/REPO` |

| Finding source | Option |
| --- | --- |
| Local findings JSON | `--findings-file PATH`; add `--offline` for a local SBOM |
| Private OSV-compatible service | `--osv-url URL` |
| Public OSV | `--allow-public-osv` |

## Use local findings

Pass a findings file when vulnerability or exploitability analysis already exists locally:

```bash
uv run --frozen vexcalibur generate \
  path/to/sbom.json \
  --offline \
  --findings-file path/to/findings.json \
  --output /tmp/vexcalibur-vex.json
```

This mode does not contact OSV. A finding must identify an SBOM component by `component_ref` or by a package URL that occurs only once. See the [local findings format](../reference/local-findings.md).

When the inventory comes from `--github-repo`, omit `--offline` because fetching the SBOM uses the network. `--findings-file` still selects local findings and prevents an OSV request.

## Use a private OSV mirror

Point `--osv-url` at the mirror's base URL:

```bash
uv run --frozen vexcalibur generate \
  path/to/private-sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

The endpoint must provide the OSV `/v1/querybatch` API used by Vexcalibur. Its
canonical base URL becomes the finding provenance by default. Use the paired
`--osv-source-name` and `--osv-source-url` options when the document needs a
public provenance alias instead. See [Use a private OSV
mirror](use-private-osv-mirror.md) for URL rules, alias guidance, limits, and
failure handling.

## Use public OSV

```{warning}
The next command sends SBOM package URLs and versions to `https://api.osv.dev`. Use it only for an inventory approved for public disclosure.
```

Pass the explicit consent flag:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```

Live OSV results change. Add a timestamp when the document metadata must stay stable:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

A fixed timestamp does not freeze live vulnerability data.

## Fetch an SBOM from GitHub

Pass `--github-repo` instead of a local input path:

<!-- github-repo-public-example:start -->
```bash
uv run --frozen vexcalibur generate \
  --github-repo vexcalibur-dev/vexcalibur \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```
<!-- github-repo-public-example:end -->

Vexcalibur requests GitHub's asynchronous SPDX 2.3 JSON report. It waits until the report is ready. It downloads the report and extracts package URL references. The resulting components use the same finding and rendering path as a local SBOM.

Fetching the SBOM and querying a vulnerability service are separate network decisions. `--github-repo` does not grant permission to send the inventory to public OSV.

Vexcalibur resolves GitHub credentials in this order:

1. the variable named by `--github-token-env`.
2. `GH_TOKEN` or `GITHUB_TOKEN` for `https://api.github.com`.
3. `gh auth token --hostname HOST`, unless `--no-gh-auth` is set.

Public repositories may work without a token, subject to rate limits. A token-backed request needs repository `Contents: read` permission.

For GitHub Enterprise, pass both the API base URL and an explicit token variable:

<!-- github-repo-enterprise-example:start -->
```bash
uv run --frozen vexcalibur generate \
  --github-repo internal/example \
  --github-api-url https://github.example.test/api/v3 \
  --github-token-env GH_ENTERPRISE_TOKEN \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```
<!-- github-repo-enterprise-example:end -->

If Vexcalibur is already installed in a GitHub Actions job, grant `contents: read` and use this step excerpt to pass the workflow token:

```yaml
permissions:
  contents: read

steps:
  - run: |
      vexcalibur generate \
        --github-repo "$GITHUB_REPOSITORY" \
        --github-token-env GITHUB_TOKEN \
        --osv-url https://osv.internal.example \
        --output vex.json
    env:
      GITHUB_TOKEN: ${{ github.token }}
```

## Run the released GitHub Action

This workflow uses the tested `v0.2.2` Action pair: Action commit
`80c930ee228c2757a4aadb51ce29a79c5066d6ca` and `vexcalibur==0.3.1`. It keeps
the vulnerability lookup local and uploads the generated VEX file only after
the generation step succeeds.

```yaml
name: Generate VEX

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  vex:
    runs-on: ubuntu-latest
    steps:
      - name: Check out the repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0

      - name: Generate CycloneDX VEX
        uses: vexcalibur-dev/vexcalibur-action@80c930ee228c2757a4aadb51ce29a79c5066d6ca # v0.2.2
        with:
          package-spec: vexcalibur==0.3.1
          args: |
            generate
            ${{ github.workspace }}/path/to/sbom.json
            --offline
            --findings-file
            ${{ github.workspace }}/path/to/findings.json
            --output
            ${{ runner.temp }}/vex.json

      - name: Upload VEX
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: cyclonedx-vex
          path: ${{ runner.temp }}/vex.json
          if-no-files-found: error
```

Replace both `path/to` values with files in your repository. A passing
**Generate CycloneDX VEX** step followed by a `cyclonedx-vex` artifact is the
success signal.

The Action and package are separate trust decisions. To update either pin, use
the Action release's compatibility declaration, pinned here to immutable
Action commit `80c930ee228c2757a4aadb51ce29a79c5066d6ca`, to select a package
version and Action commit tested together:
[compatibility declaration](https://github.com/vexcalibur-dev/vexcalibur-action/blob/80c930ee228c2757a4aadb51ce29a79c5066d6ca/docs/reference/compatibility.md)

## Read XML input

Pass a CycloneDX XML file in the same position as JSON:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-xml-1.5-simple.xml \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --output /tmp/vexcalibur-vex.json
```

## Write to standard output

Omit `--output`:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --offline \
  --findings-file tests/fixtures/findings/all-analysis-states.json
```

## Check basic output fields

Parse the file and check its format discriminators:

```bash
python - <<'PY'
import json
from pathlib import Path

vex = json.loads(Path("/tmp/vexcalibur-vex.json").read_text())
assert vex["bomFormat"] == "CycloneDX"
assert vex["specVersion"] == "1.6"
print(f"found {len(vex.get('vulnerabilities', []))} VEX entries")
PY
```

This is a sanity check, not validation against the full CycloneDX JSON schema.

See the [CLI reference](../reference/cli.md) for accepted SBOM versions, size limits, option conflicts, token behavior, and exit messages. See the [output reference](../reference/cyclonedx-vex-output.md) for grouping and determinism rules.
