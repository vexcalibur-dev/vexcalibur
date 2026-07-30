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

The validator uses three exit statuses:

- `0`: the report, document binding, and policy passed.
- `1`: validation passed, but the exploitable-count policy rejected the report.
- `2`: command usage, file integrity, JSON, schema, or document validation
  failed. Expected failures print one concise error to standard error without a
  traceback.

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

A workflow recipe must pin a package release that already contains
`--execution-report`. This default-branch page cannot name that future release,
so it deliberately omits the Action recipe for now. Use the source-checkout
procedure above until the release notes and the installed
`vexcalibur generate --help` output confirm support.

After publication, open the release's immutable tag on GitHub and use the
`docs/` tree and schema from that tag. GitHub Pages and Read the Docs describe
the default branch; they are not immutable release documentation. Keep the
schema and package on the same tag, pin the companion Action to a full commit,
validate the report before reading it, and upload neither file when validation
fails.

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
