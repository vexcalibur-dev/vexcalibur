# Generate CycloneDX VEX

Use `vexcalibur generate` when you have a supported CycloneDX JSON or XML SBOM, or when you want to fetch package inventory from a GitHub Dependency Graph SBOM, and need CycloneDX 1.6 VEX JSON based on OSV-compatible vulnerability findings.

## Generate From A Public Fixture

The repository fixture is safe to use in public-service examples. The command must still opt in before contacting the public OSV API:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```

Live OSV results can change. Add `--timestamp` when tests or review steps need deterministic document metadata:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv \
  --timestamp 2026-06-23T00:00:00Z \
  --output /tmp/vexcalibur-vex.json
```

## Generate With A Private OSV Mirror

Use `--osv-url` for private mirrors. Do not pass `--allow-public-osv` for private SBOMs:

```bash
uv run --frozen vexcalibur generate \
  path/to/sbom.json \
  --osv-url https://osv.internal.example \
  --output /tmp/vexcalibur-vex.json
```

The configured endpoint must implement the OSV query API shape used by Vexcalibur's provider client.

## Generate From A GitHub Repository SBOM

Use `--github-repo OWNER/REPO` when the package inventory should come from
GitHub Dependency Graph instead of a local SBOM file:

<!-- github-repo-public-example:start -->
```bash
uv run --frozen vexcalibur generate \
  --github-repo vexcalibur-dev/vexcalibur \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```
<!-- github-repo-public-example:end -->

Vexcalibur requests an SPDX JSON report from GitHub's asynchronous SBOM API,
polls until the report is ready, downloads it, and extracts package URL
references from that SPDX document. It then uses the same vulnerability source
and CycloneDX VEX rendering pipeline as local CycloneDX input.

Token resolution for `--github-repo` is designed to work in local shells and CI:

- Public repositories can be requested without a token, subject to GitHub API
  rate limits.
- `--github-token-env NAME` reads a token from the named environment variable.
- Without `--github-token-env`, Vexcalibur checks `GH_TOKEN` and
  `GITHUB_TOKEN` for `https://api.github.com`.
- For non-default GitHub API hosts, pass `--github-token-env NAME` explicitly
  or rely on the `gh auth token` fallback for that host.
- If no token environment variable is set, Vexcalibur tries `gh auth token`.
  Pass `--no-gh-auth` to disable that fallback.

Use `--github-api-url` for GitHub Enterprise API hosts:

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

In GitHub Actions, grant `contents: read` and pass the workflow token. This is
a step excerpt that assumes Vexcalibur is already installed in the job:

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

When using the companion action, pass the same CLI arguments through `args`:

```yaml
permissions:
  contents: read

steps:
  - uses: vexcalibur-dev/vexcalibur-action@d9967565ac550fd5a22feb8f64ca966e51444cc5
    with:
      package-spec: vexcalibur==0.1.0
      args: |
        generate
        --github-repo
        ${{ github.repository }}
        --github-token-env
        GITHUB_TOKEN
        --osv-url
        https://osv.internal.example
        --output
        vex.json
    env:
      GITHUB_TOKEN: ${{ github.token }}
```

Fetching an SBOM from GitHub is a network operation. Passing that SBOM-derived
package inventory to public OSV is a separate network boundary and still
requires `--allow-public-osv`.

## Generate Offline From Local Findings

Use `--findings-file` when another trusted process has already produced vulnerability findings or exploitability analysis. This mode never contacts OSV.

```bash
uv run --frozen vexcalibur generate \
  path/to/sbom.json \
  --offline \
  --findings-file path/to/findings.json \
  --output /tmp/vexcalibur-vex.json
```

The findings file uses Vexcalibur's [local findings JSON format](../reference/local-findings.md). Local findings must identify SBOM components by `component_ref` or by a package URL that appears exactly once in the SBOM.

## Choose A Source Mode For CI

Use exactly one vulnerability source mode in automated jobs:

- Public fixture or intentionally public package inventory: use `--allow-public-osv`.
- Private SBOM with an internal OSV-compatible service: use `--osv-url https://osv.internal.example`.
- Offline or pre-reviewed vulnerability data from a local SBOM file: use
  `--offline --findings-file path/to/findings.json`.
- GitHub-hosted package inventory: use `--github-repo OWNER/REPO` and choose one
  vulnerability source mode.

Do not pass `--allow-public-osv` for private SBOMs. Do not combine `--findings-file` with `--allow-public-osv` or `--osv-url`; local findings mode is the no-network path.

## Write To Standard Output

Omit `--output` to write the VEX JSON to standard output:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --allow-public-osv
```

## Generate From XML Input

Use the same command for CycloneDX XML SBOM input:

```bash
uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-xml-simple.xml \
  --allow-public-osv \
  --output /tmp/vexcalibur-vex.json
```

## Supported Input

All `generate` source modes currently support:

- CycloneDX JSON SBOMs with `specVersion` `1.4`, `1.5`, or `1.6`; JSON input must be UTF-8.
- CycloneDX XML SBOMs rooted at `bom` in the `http://cyclonedx.org/schema/bom/1.4`, `/1.5`, or `/1.6` namespace; XML may use parser-detected XML encodings such as UTF-8 or UTF-16, and DTD, entity, and external-reference declarations are rejected.
- GitHub Dependency Graph SBOM input from `--github-repo OWNER/REPO`; GitHub
  generates an SPDX JSON report and Vexcalibur extracts package URL references
  from package `externalRefs`.
- GitHub API URLs must use HTTPS and must not include userinfo, query strings,
  or fragments. For GitHub Enterprise Server, use the API base URL such as
  `https://github.example.test/api/v3`.
- Token-backed GitHub SBOM requests need repository `Contents: read`
  permission. Public repositories can be requested without a token, subject to
  GitHub API rate limits.
- Local SBOM files and GitHub SBOM report downloads up to 10 MiB.
- Up to 10,000 components.
- Component nesting up to 50 levels.
- Unique component refs for components with package URLs.

OSV-backed generation also requires components with package URLs and versions from either the PURL, CycloneDX `version` field, or GitHub SPDX `versionInfo`. It intentionally fails when no precise query set can be built. That is safer than producing an empty VEX document that could look authoritative.

Local findings mode can produce an empty VEX document when the findings file explicitly contains no findings.

## Current Limitations

The current generator does not yet support:

- Policy-driven VEX state selection for OSV-derived findings.
- Legacy `vexy` XML output or CycloneDX `1.4` VEX output.

See the [CycloneDX VEX output reference](../reference/cyclonedx-vex-output.md)
for the generated document contract.
