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
version constant. In an editable Git checkout, Vexcalibur also requires the
generated commit identifier to match the checkout's `HEAD`. The all-zero digest
is a placeholder; a real report contains the SHA-256 of its generated
document.

The file is canonical minified JSON with one trailing newline. Object key
order is stable, but consumers should use JSON keys rather than byte positions.
The [JSON Schema](../execution-report-v1.schema.json) is the structural
machine-readable contract. It uses JSON Schema Draft 2020-12 and rejects
unknown properties. JSON Schema treats a number such as `1.0` as an integer
when it has no fractional part, but Vexcalibur's canonical report contract
requires an integer JSON token. Use
`parse_generation_execution_report` or the tested
[consumer validator](../examples/validate_execution_report.py) to apply those
exact-type checks before schema validation.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | exact integer token | Exactly `1`. Booleans and decimal forms such as `1.0` are rejected. The report schema changes independently of the package version. |
| `command` | string | Exactly `generate`. |
| `vexcalibur_version` | string | Installed Vexcalibur distribution version loaded by the process. It must match package metadata; an editable Git checkout must also identify its current `HEAD`. The value has 1–128 characters from `[0-9A-Za-z.!+_-]`, with an alphanumeric first character. |
| `inventory_source` | string | One inventory category from the table below. |
| `finding_source` | string | One finding category from the table below. |
| `output_format` | string | `cyclonedx`, `openvex`, `csaf`, or `custom`. |
| `component_count` | exact integer token from 0 through 10,000,000 | Normalized components sent to the finding source. |
| `finding_count` | exact integer token from 0 through 10,000,000 | Normalized findings sent to the renderer. |
| `analysis_state_counts` | object | Exact positive integer tokens through 10,000,000, keyed by `resolved`, `exploitable`, `in_triage`, `false_positive`, or `not_affected`. States with zero findings are omitted. |
| `document.sha256` | string | 64-character lowercase hexadecimal SHA-256 digest of the exact rendered UTF-8 document. |
| `document.bytes` | exact integer token from 0 through 26,214,400 | Length of the exact rendered document in UTF-8 bytes. The maximum is the 25 MiB generation limit. |

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
Python embedding that injects an OSV client records `custom`, even when that
client contacts an OSV-compatible endpoint. Reserved OSV categories describe
only the exact built-in client selected by Vexcalibur. Other custom sources and
renderers also use `custom`. The value records the extension boundary without
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
document metadata. Any later failure leaves no stale success marker from that
transaction.

Stale-report cleanup briefly takes the report directory lock while Vexcalibur
prepares the destination. The locks that coordinate the document and report
replacements begin during commit, after generation. The replacements are
individually atomic, but the pair is not an atomic two-file commit. A failure
after Vexcalibur replaces the document can leave that document in place without
a report.

Another process can publish a newer report after the failed transaction removes
the old one. It can also replace a successful report after this command exits.
Give each job its own output directory when consumers must retain a one-to-one
mapping between a VEX document and its report.

After generation, Vexcalibur publishes in this order:

1. Construct and validate the complete report.
2. Stage the report and any file-based VEX output in private mode-`0600` files,
   then flush them.
3. Keep the staged files open, verify their filesystem identities, and acquire
   destination-directory locks in stable order.
4. Remove any report created after the initial cleanup. If removal fails,
   publish nothing.
5. Publish the VEX document and check the destination paths again for aliases.
6. Publish the report last, then release the locks.

Standard output follows a related sequence, but its bytes cannot be rolled back
after a partial write. Vexcalibur first takes a lock for the report name. While
holding that lock, it briefly takes the directory lock and removes an
intervening report. If cleanup fails, standard output remains unchanged.

Vexcalibur releases the directory lock before it writes and flushes standard
output. It then takes the directory lock again, removes any report created by a
process that didn't use the sequence lock, and publishes the new report. The
per-report lock remains held through the complete sequence. A blocked stream
therefore serializes another writer for the same report path without blocking a
different report path in that directory.

Each atomic replacement is followed by a directory `fsync`. A failed file or
directory flush makes the command fail. Vexcalibur removes an unpublished
temporary file when it can, but callers must not treat leftover private
temporary files as completed reports.

If Python handles an interruption, including `SIGINT`, after report publication
but before successful finalization, Vexcalibur attempts to remove the report
when the path still names the file it published. The document may remain. A
concurrent replacement at the report path is left alone. If descriptor cleanup
is interrupted after Vexcalibur can no longer prove that identity, it leaves the
report in place instead of risking removal of another file. Treat both paths as
indeterminate after every nonzero exit.

Abrupt termination does not run that cleanup. `SIGKILL` always stops the
process immediately, and the default `SIGTERM` handler also bypasses Python
unwinding. Either signal can leave a report that was already published even
though the process did not exit successfully. Consumers must require exit
status `0` and validate the report against the document.

A parent-directory change stops the operation instead of redirecting either
write. The parent must already exist and must be readable, writable, and
searchable by the process. Its filesystem must support descriptor-relative
operations, advisory `flock`, and `fsync`.

Each destination parent contains a persistent `.vexcalibur-locks` directory.
Vexcalibur requires that directory to be owned by the current user and sets its
mode to `0700`. One `directory.lock` file coordinates every report-aware
publication in that parent. Standard-output transactions also use a
lock whose name starts with `stdout-`, continues with the 64-character
lowercase SHA-256 digest of the report leaf name, and ends with `.lock`. Writers
for that report therefore keep their stream and report order.

Vexcalibur requires each lock to be a regular file owned by the current user
with one link, and sets its mode to `0600`. The fixed directory lock name gives
processes the same publication point even when they use different filesystem
encodings.

Do not use a destination parent that another user can write. A different user
can create the fixed coordination directory first and prevent publication.
Directly shared multi-user output directories are not supported.

Vexcalibur retries a contended directory or per-report sequence lock for up to
10 seconds. If the lock remains busy, publication fails without leaving a
completed report. The coordination directory and lock files remain in place
for later runs.
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

Python embeddings can construct and serialize an execution report on every
supported platform. The caller writes the VEX document and report separately,
so those writes do not provide the CLI's transaction guarantees.

The report is limited to 16 KiB. A missing or stale package version, invalid
report value, size violation, or write failure makes the command fail.

The VEX file and report are separate atomic writes, not one two-file
transaction. A later report-write failure can leave the replaced VEX file, or
the document in captured standard output, even though the command exits
nonzero. Automation must treat exit status `0` and a valid report as the
success condition.

The directory locks prevent cooperating Vexcalibur processes from interleaving
their file commits. The per-report sequence lock preserves stdout and report
ordering when those processes use the same report path. These locks do not
coordinate every program that can write the directory. The path checks and
advisory locks also cannot protect against a process that ignores the lock,
runs as the same user and changes the coordination files, or changes an output
after publication. Use a per-job directory that is isolated from untrusted
processes, especially processes that share the same user ID.

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
