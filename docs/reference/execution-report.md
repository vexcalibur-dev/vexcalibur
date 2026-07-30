# Generation execution report

`vexcalibur generate` can write a versioned JSON report for downstream
automation on Linux and macOS. The report describes what Vexcalibur processed
without repeating package names and URLs, vulnerability IDs, repository names,
filesystem paths, provider URLs, credentials, or exception text.

Counts, source categories, the package version, and a document digest can still
be sensitive in some environments. Apply the same access policy you use for
other build metadata.

Request the report with `--execution-report PATH`:

```bash
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

uv run --frozen vexcalibur generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --offline \
  --output "$work_dir/vex.json" \
  --execution-report "$work_dir/execution-report.json"
```

Run this source-checkout example from the repository root after
`uv sync --frozen`. It creates a private temporary directory and removes that
directory when the shell exits. The
[consumption guide](../how-to/consume-execution-report.md) includes the complete
setup and validation sequence.

Success writes both files and exits with status `0`. The report describes the
exact UTF-8 bytes in `vex.json`.

## Schema

Schema version 1 has this structure:

```json
{
  "analysis_state_counts": {
    "in_triage": 4
  },
  "command": "generate",
  "component_count": 122,
  "document": {
    "bytes": 824,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "finding_count": 4,
  "finding_source": "local_file",
  "inventory_source": "sbom_file",
  "output_format": "cyclonedx",
  "schema_version": 1,
  "vexcalibur_version": "EXAMPLE"
}
```

`EXAMPLE` stands for the installed package version. Vexcalibur reads that
value from Python package metadata; the source tree does not contain a release
version constant. The all-zero digest is also a placeholder; a real report
contains the SHA-256 of its generated document.

The file is canonical minified JSON with one trailing newline. Object key
order is stable, but consumers should use JSON keys rather than byte positions.
The [JSON Schema](../execution-report-v1.schema.json) is the machine-readable
contract. It uses JSON Schema Draft 2020-12 and rejects unknown properties.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Exactly `1`. The report schema changes independently of the package version. |
| `command` | string | Exactly `generate`. |
| `vexcalibur_version` | string | Installed Python package version, 1–128 characters from `[0-9A-Za-z.!+_-]`; the first character is alphanumeric. |
| `inventory_source` | string | One inventory category from the table below. |
| `finding_source` | string | One finding category from the table below. |
| `output_format` | string | `cyclonedx`, `openvex`, `csaf`, or `custom`. |
| `component_count` | nonnegative integer | Normalized components sent to the finding source. |
| `finding_count` | nonnegative integer | Normalized findings sent to the renderer. |
| `analysis_state_counts` | object | Positive counts keyed by `resolved`, `exploitable`, `in_triage`, `false_positive`, or `not_affected`. States with zero findings are omitted. |
| `document.sha256` | string | 64-character lowercase hexadecimal SHA-256 digest of the exact rendered UTF-8 document. |
| `document.bytes` | integer from 0 through 26,214,400 | Length of the exact rendered document in UTF-8 bytes. The maximum is the 25 MiB generation limit. |

`component_count` is not the number of raw entries in an SBOM.
`finding_count` is not a severity threshold, policy decision, or proof that the
inventory is safe. A zero-finding report says only that the selected source
returned no normalized findings for this operation.

The sum of `analysis_state_counts` always equals `finding_count`. With no
findings, the object is empty.

## Source categories

`inventory_source` uses one of these values:

| Value | Input |
| --- | --- |
| `sbom_file` | Local CycloneDX JSON or XML |
| `github_dependency_graph` | GitHub Dependency Graph SBOM API |
| `custom` | Inventory supplied by an embedding through the Python API |

`finding_source` uses one of these values:

| Value | Input |
| --- | --- |
| `local_file` | `--findings-file` |
| `public_osv` | The canonical `https://api.osv.dev` endpoint, with explicit consent |
| `custom_osv` | A caller-selected, noncanonical OSV-compatible endpoint, whether privately or publicly reachable |
| `custom` | Another finding source classified by an embedding through the Python API |

The categories distinguish the official public OSV service from a caller-chosen
endpoint without exposing the source path, repository, or service URL. A
non-root-equivalent path or nonstandard port on the `api.osv.dev` host is
`custom_osv`, not `public_osv`. OSV endpoint URLs with queries or fragments are
invalid and fail before generation.

The CLI emits only its concrete inventory, finding, and output categories. A
Python embedding can use `custom` when it owns a source or renderer that does
not match a built-in category. The value records that boundary without
pretending the extension is CycloneDX, OSV, or a built-in VEX format.

## Write behavior

Vexcalibur first asks its normal command parser to validate the complete
`generate` argument list. Only then does it remove a stale report. This order
prevents a partial parse from mistaking an inventory, findings file, or VEX
output for disposable report data.

Help, completion, unknown options, missing files, and other parser failures
leave the candidate path unchanged because Vexcalibur cannot prove the path is
a report. Once parsing succeeds, Vexcalibur binds the destination and removes
an existing report before it validates timestamps, source combinations, or
document metadata. Any later failure therefore leaves no stale success marker.

After generation, Vexcalibur constructs and validates the complete report. It
then stages the report in a private file and stages file-based VEX output the
same way. Both temporary files are mode `0600` and are flushed before
publication. Vexcalibur keeps each staged file open, verifies its filesystem
identity before and after replacement, and locks each destination directory.
It acquires multiple directory locks in a stable order. Vexcalibur publishes
the VEX document first, checks the paths again for aliases, and publishes the
report last. Standard output follows the same order except that its bytes
cannot be rolled back after a partial write. Vexcalibur holds the report
publication lock while it writes and flushes standard output, then publishes
the report before releasing that lock.

Each atomic replacement is followed by a directory `fsync`. A failed file or
directory flush makes the command fail. Vexcalibur removes an unpublished
temporary file when it can, but callers must not treat leftover private
temporary files as completed reports.

A parent-directory change stops the operation instead of redirecting either
write. The parent must already exist and must be readable, writable, and
searchable by the process. Its filesystem must support descriptor-relative
operations, advisory `flock`, and `fsync`.

Each destination parent contains a persistent `.vexcalibur-locks` directory.
Vexcalibur requires that directory to be owned by the current user and sets its
mode to `0700`. One `directory.lock` file coordinates every report-aware
publication in that parent. Vexcalibur requires the file to be a regular file
owned by the current user with one link, and sets its mode to `0600`. This
fixed name gives processes the same coordination point even when they use
different filesystem encodings.

Vexcalibur retries a contended directory lock for up to 10 seconds. If the lock
remains busy, publication fails without leaving a completed report. The
coordination directory and lock file remain in place for later runs.
Vexcalibur reserves the complete `.vexcalibur-locks` directory namespace.
Neither an output nor a report may name the directory, a file inside it, or a
hard link to an acquired coordination lock.

The report path:

- must be absent or name a regular file or symbolic link, not a directory,
  FIFO, socket, or device;
- must not alias the inventory, local findings, or VEX output path;
- must not alias redirected standard output or standard error;
- must have an existing parent directory.

When `--output` is used, its path has the same leaf-type and parent-directory
requirements.

Alias checks cover existing filesystem identity, including hard links, and
conservatively treat Unicode-normalized, case-folded names in one parent
directory as equal. Vexcalibur checks again after it publishes file-based VEX
output.

Publishing replaces the report path and, in report mode, the VEX output path.
The resulting files have mode `0600`. Their owner and group follow the process
and filesystem rules for a new file, including any set-group-ID parent
directory behavior. Previous ownership and mode are not preserved. A symbolic
link or hard-link path is replaced as a directory entry. Vexcalibur does not
write through that link to the old target.

Use a new destination when existing output must survive a failed operation.
Once replacement starts, a failed directory flush or path verification does
not restore the previous file. Vexcalibur removes its replacement when it can,
so the path may be absent even though it held valid output before the command.

The `--execution-report` CLI option and its coordinated publication transaction
are not supported on Windows. A Windows CLI request fails before Vexcalibur
removes the candidate path, reads an inventory, or writes VEX output. Calls
that omit `--execution-report` keep the existing Windows behavior.

The {ref}`Python API <execution-reports-python-api>` can construct and serialize
an execution report on every supported platform. The caller writes the VEX
document and report separately, so those writes do not provide the CLI's
transaction guarantees.

The report is limited to 16 KiB. A missing package version, invalid report
value, size violation, or write failure makes the command fail.

The VEX file and report are separate atomic writes, not one two-file
transaction. A later report-write failure can leave the replaced VEX file, or
the document in captured standard output, even though the command exits
nonzero. Automation must treat exit status `0` and a valid report as the
success condition.

The directory locks prevent cooperating Vexcalibur processes from interleaving
their document and report commits. They do not coordinate every program that
can write the directory. The path checks and advisory locks also cannot protect
against a process that ignores the lock, runs as the same user and changes the
coordination files, or changes an output after publication. Use a per-job
directory that is isolated from untrusted processes, especially processes that
share the same user ID.

An embedding must also serialize concurrent transactions that share one
writable standard-output stream but use different report destinations. The
directory lock coordinates the report destination; it cannot identify an
arbitrary shared stream as another transaction's output.

## Compatibility

The option is additive on supported systems. Calls that omit
`--execution-report` retain the existing text-mode output and Python API
behavior.

Vexcalibur v0.4.2 and earlier do not include `--execution-report`. Before you
depend on the option, verify the installed command:

```bash
vexcalibur generate --help | grep -- --execution-report
```

An exit status of `0` means the installed command exposes the option.

Consumers should reject an unknown `schema_version`. They should not infer a
schema from `vexcalibur_version`.

Validate the closed-world JSON Schema, check that state counts sum to
`finding_count`, and verify the digest and byte count before trusting a report.
The [consumption guide](../how-to/consume-execution-report.md) shows the complete
sequence. Python embeddings can use `parse_generation_execution_report` to
enforce Vexcalibur's canonical serialization contract before applying their
own document and policy checks.
