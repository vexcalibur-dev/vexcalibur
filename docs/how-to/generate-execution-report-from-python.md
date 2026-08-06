# Generate an execution report from Python

Use the report-aware Python API when an embedding needs the same versioned
summary on Windows, Linux, or macOS. The Python API constructs and validates the
report, but your application owns file publication.

## Prepare the checkout

The checked-in example uses local test fixtures and makes no network requests.
Run it from the repository root after installing the locked environment:

```bash
uv sync --frozen
```

The example imports only from `vexcalibur.api`. It handles SBOM, findings,
rendering, package-metadata, and report-parse failures separately.

```{literalinclude} ../examples/generate_execution_report.py
:language: python
:linenos:
```

## Generate and validate both files

Choose a new child of the repository root so the parent already exists. The
example refuses to replace the directory or either output file.

On POSIX, the example creates the directory with mode `0700` and each file with
mode `0600`. On Windows, Python inherits access control lists (ACLs) from the
parent; the example does not make an existing parent private. Run it only from
a directory whose ACL already restricts access to the intended user.

The two final-path writes are independent and are not atomic. A write or
`fsync` failure can leave a partial VEX file or execution report. Use the CLI
instead when a POSIX embedding needs coordinated publication.

Run this one-line command from Bash or PowerShell:

```console
uv run --frozen python docs/examples/generate_execution_report.py vexcalibur-python-report
```

A successful run prints both paths:

```text
wrote vexcalibur-python-report/vex.json and vexcalibur-python-report/execution-report.json
```

The example parses the serialized report through
`parse_generation_execution_report()` before either file is written. A parse
failure stops the run.

Use `result.rendered_bytes` for the VEX file and serialize the report from the
same `GenerationResult`. Don't render again or calculate counts from the VEX
document; either step can make the report describe different bytes.

## Handle publication in the embedding

The example uses exclusive creation and refuses to replace existing paths. On
Windows, privacy depends on the parent ACL described above. On every platform,
a failed direct write can leave a partial file, and a report failure can leave
the VEX file behind.

Applications that need coordinated replacement on Linux or macOS should invoke
the CLI with `--execution-report`. The CLI publishes VEX first and the report
last under its destination locks. The supported Python facade does not expose
that filesystem transaction.

Catch `GenerationReportMetadataError` when installed package metadata cannot
identify the loaded code. Catch `GenerationExecutionReportParseError` when
validating report bytes received from another process. The [Python API
reference](../reference/python-api.rst) lists the complete report types and
failure contracts; the [execution report reference](../reference/execution-report.md)
defines the JSON fields and security boundary.
