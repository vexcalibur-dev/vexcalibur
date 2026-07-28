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
  docs/execution-report-v1.schema.json
```

The final line is the success signal. Apply policy only after it appears. For
example, a workflow can reject any nonzero `exploitable` count, but that is the
workflow's policy rather than a conclusion made by Vexcalibur.

The validator is the tested example from this checkout. It opens the report,
schema, and document in nonblocking mode, checks each opened descriptor, and
rejects symbolic links and special files. It rejects an opened document larger
than 25 MiB before reading and hashing it, even though the schema carries the
same maximum. It accepts only the reviewed schema bytes from the same checkout;
a changed or substituted schema is rejected before JSON Schema evaluation.
Schema references cannot trigger network requests.

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
