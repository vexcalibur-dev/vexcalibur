# Consume a generation execution report

Use an execution report when automation needs counts and document integrity
metadata without parsing a VEX format. Treat the report and VEX document as one
result: accept neither unless the generation command and every validation step
succeeds.

This guide requires Linux or macOS, Bash, Git, and `uv`. It uses the
repository's locked development environment because that environment includes
a JSON Schema Draft 2020-12 validator.

Releases that predate execution-report support do not include this option. Use
an immutable release or reviewed full commit SHA, then confirm that
`vexcalibur generate --help` lists `--execution-report` before you update
automation.

Replace `REPLACE_WITH_FULL_COMMIT_SHA` below with the lowercase, 40-character
commit SHA for the release you selected. Run these commands from a clean
working directory:

```bash
set -euo pipefail

revision="REPLACE_WITH_FULL_COMMIT_SHA"
if [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'revision must be a full lowercase commit SHA\n' >&2
  exit 2
fi
git clone https://github.com/vexcalibur-dev/vexcalibur.git
cd vexcalibur
git checkout --detach "${revision}"
test "$(git rev-parse HEAD)" = "${revision}"
uv sync --frozen
uv run --frozen vexcalibur generate --help | grep -- --execution-report
```

The final command must print the option. Use the schema from that same checkout
and run the remaining commands from the repository root.

## Generate both files

Use a new directory for each operation. This prevents accidental reuse of an
old report, but it does not authenticate either output. Run the job somewhere
an untrusted process with the same user ID cannot modify the directory.

```bash
set -euo pipefail

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --offline \
  --output "${work_dir}/vex.json" \
  --execution-report "${work_dir}/execution-report.json"
```

The command exits with status `0` only after it writes both paths. Because the
shell uses `set -e`, validation does not run after a failed generation. Both
files have mode `0600`.

## Validate the report and document

Validate the closed-world schema before reading fields. Then check the
cross-field state total and bind the report to the exact VEX bytes:

```bash
uv run --frozen python docs/examples/validate_execution_report.py \
  "${work_dir}/execution-report.json" \
  "${work_dir}/vex.json" \
  docs/execution-report-v1.schema.json \
  --max-exploitable 1
```

The command prints `execution report verified` and exits with status `0`. The
`--max-exploitable 1` policy accepts the one exploitable finding in the example
fixture.

Set the limit to zero when your workflow must reject every exploitable finding:

```bash
uv run --frozen python docs/examples/validate_execution_report.py \
  "${work_dir}/execution-report.json" \
  "${work_dir}/vex.json" \
  docs/execution-report-v1.schema.json \
  --max-exploitable 0
```

The example report fails that policy with status `1` and this stable error:

```text
execution report rejected: exploitable count 1 exceeds maximum 0
```

The validator applies policy to the object it already validated. It does not
open or parse the report a second time.

The validator is the tested example from this checkout. It opens the report,
schema, and document in nonblocking mode, checks each opened descriptor, and
rejects symbolic links and special files. It rejects an opened document larger
than 25 MiB before reading and hashing it, even though the schema carries the
same maximum. It accepts only the reviewed schema bytes from the same checkout;
a changed or substituted schema is rejected before JSON Schema evaluation.
Schema references cannot trigger network requests.

## Consume reports in GitHub Actions

The companion Action passes ordinary Vexcalibur arguments through to the
installed package. This workflow keeps the VEX document and report in
`${{ runner.temp }}`, validates both against the schema from the matching
Vexcalibur release, and uploads them only after validation succeeds:

```yaml
permissions:
  contents: read

steps:
  - name: Check out the matching Vexcalibur schema and validator
    uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
    with:
      repository: vexcalibur-dev/vexcalibur
      ref: v0.5.0
      path: .vexcalibur-source
      persist-credentials: false

  - name: Generate VEX and its execution report
    uses: vexcalibur-dev/vexcalibur-action@cc570fb0ab80df3f4b1e31c0608b95c0707d5b66
    with:
      package-spec: vexcalibur==0.5.0
      args: |
        generate
        ${{ github.workspace }}/.vexcalibur-source/tests/fixtures/sbom/cyclonedx-json-simple.json
        --offline
        --findings-file
        ${{ github.workspace }}/.vexcalibur-source/tests/fixtures/findings/all-analysis-states.json
        --output
        ${{ runner.temp }}/vex.json
        --execution-report
        ${{ runner.temp }}/execution-report.json

  - name: Set up uv
    uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2
    with:
      version-file: .vexcalibur-source/.tool-versions
      enable-cache: true

  - name: Validate the report and apply policy
    run: |
      set -euo pipefail
      cd "${GITHUB_WORKSPACE}/.vexcalibur-source"
      uv sync --frozen --extra docs
      uv run --frozen python docs/examples/validate_execution_report.py \
        "${RUNNER_TEMP}/execution-report.json" \
        "${RUNNER_TEMP}/vex.json" \
        docs/execution-report-v1.schema.json \
        --max-exploitable 1

  - name: Upload validated VEX artifacts
    uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
    with:
      name: vexcalibur-vex
      path: |
        ${{ runner.temp }}/vex.json
        ${{ runner.temp }}/execution-report.json
      if-no-files-found: error
```

Replace the fixture paths and policy limit for your repository. The `v0.5.0`
tag is immutable and matches `vexcalibur==0.5.0`; the Action itself is pinned
to the reviewed full commit. Package releases before `0.5.0` reject
`--execution-report`.

## Keep the trust boundary explicit

The report omits package names and URLs, vulnerability IDs, repository names,
filesystem paths, provider URLs, credentials, and exception text. Its counts,
categories, package version, and document digest may still reveal operational
information. Store and publish it according to the same policy as other build
metadata.

The digest detects a mismatch between the two files. It does not prove who
created them. Isolate the working directory from untrusted processes that run
as the same user, and use artifact attestations or signatures when you need
provenance after the job ends.

Reject unknown schema versions and properties. Do not choose a schema from
`vexcalibur_version`, and do not use an old report when generation exits
nonzero.
