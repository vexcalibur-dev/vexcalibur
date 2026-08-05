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

Choose a new output directory so the example cannot replace an existing file:

```bash
uv run --frozen python docs/examples/generate_execution_report.py \
  /tmp/vexcalibur-python-report
```

A successful run prints both paths:

```text
wrote /tmp/vexcalibur-python-report/vex.json and /tmp/vexcalibur-python-report/execution-report.json
```

The example parses the serialized report through
`parse_generation_execution_report()` before either file is written. A parse
failure stops the run.

Use `result.rendered_bytes` for the VEX file and serialize the report from the
same `GenerationResult`. Don't render again or calculate counts from the VEX
document; either step can make the report describe different bytes.

## Handle publication in the embedding

The example creates private files with exclusive creation and refuses to
replace existing paths. This works on every supported Python platform, but the
two writes are independent. If the report write fails, the VEX file may remain.

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
