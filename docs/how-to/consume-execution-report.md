# Consume a generation execution report

Use an execution report when automation needs counts and document integrity
metadata without parsing a VEX format. Treat the report and VEX document as one
result: accept neither unless the generation command and every validation step
succeeds.

This guide requires Linux or macOS, Bash, Git, and `uv`. It uses the
repository's locked development environment because that environment includes
a JSON Schema Draft 2020-12 validator.

Vexcalibur v0.4.2 and earlier do not include execution reports. Use an
immutable release or a reviewed pull-request commit, then confirm that
`vexcalibur generate --help` lists `--execution-report` before you update
automation.

For a release, set `RELEASE_TAG` to the exact version you reviewed. This
sequence fetches only that tag from the official repository, requires an
annotated tag that points directly to a commit, and derives the checkout SHA
from the fetched ref:

```bash
set -euo pipefail

RELEASE_TAG="${RELEASE_TAG:?set RELEASE_TAG to the reviewed release tag}"
if [[ ! "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
  printf 'RELEASE_TAG must be a bounded vMAJOR.MINOR.PATCH release tag\n' >&2
  exit 2
fi

git init vexcalibur
cd vexcalibur
git remote add origin https://github.com/vexcalibur-dev/vexcalibur.git
git fetch --depth=1 origin \
  "refs/tags/${RELEASE_TAG}:refs/tags/${RELEASE_TAG}"

read -r object_type _ target_type release_sha < <(
  git for-each-ref \
    --format='%(objecttype) %(objectname) %(*objecttype) %(*objectname)' \
    "refs/tags/${RELEASE_TAG}"
)
test "${object_type}" = "tag"
test "${target_type}" = "commit"
[[ "${release_sha}" =~ ^[0-9a-f]{40}$ ]]

git checkout --detach "${release_sha}"
test "$(git rev-parse HEAD)" = "${release_sha}"
uv sync --frozen
uv run --frozen vexcalibur generate --help | grep -- --execution-report
```

For unreleased work, record the full SHA you reviewed and fetch the pull
request's head ref. The comparison fails if the pull request moved after your
review:

```bash
set -euo pipefail

PR_NUMBER="${PR_NUMBER:?set PR_NUMBER to the reviewed pull request}"
REVIEWED_SHA="${REVIEWED_SHA:?set REVIEWED_SHA to its reviewed full commit SHA}"
[[ "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]
[[ "${REVIEWED_SHA}" =~ ^[0-9a-f]{40}$ ]]

git init vexcalibur
cd vexcalibur
git remote add origin https://github.com/vexcalibur-dev/vexcalibur.git
git fetch --depth=1 origin \
  "refs/pull/${PR_NUMBER}/head:refs/remotes/origin/reviewed-pr"
test "$(git rev-parse refs/remotes/origin/reviewed-pr)" = "${REVIEWED_SHA}"
git checkout --detach "${REVIEWED_SHA}"
uv sync --frozen
uv run --frozen vexcalibur generate --help | grep -- --execution-report
```

The final command must print the option. Use the schema and validator from that
same checkout, and run the remaining commands from the repository root.

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
  failed. Validation failures print one concise error to standard error without
  a traceback. Command-usage failures use `argparse`'s usage and error output.

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

The validator is the tested example from this checkout. It first requires
exact Python integers because JSON Schema treats values such as `1.0` as
integers when they have no fractional part. It then opens the report, schema,
and document in nonblocking mode, checks each opened descriptor, and rejects
symbolic links and special files. It rejects an opened document larger than
25 MiB before reading and hashing it. It accepts only the reviewed schema bytes
from the same checkout; a changed or substituted schema is rejected before
JSON Schema evaluation. Schema references cannot trigger network requests.

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
