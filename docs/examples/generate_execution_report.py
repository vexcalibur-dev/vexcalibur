#!/usr/bin/env python3
"""Generate matching VEX and execution-report bytes with the Python API."""

import argparse
import os
from pathlib import Path

from vexcalibur.api import (
    GenerationExecutionReportParseError,
    GenerationReportMetadataError,
    LocalFindingsError,
    SbomError,
    VexRenderError,
    generate_vex_from_local_findings_result,
    parse_generation_execution_report,
)


def _write_new_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main(output_directory: Path) -> None:
    try:
        result = generate_vex_from_local_findings_result(
            input_file=Path("tests/fixtures/sbom/cyclonedx-json-simple.json"),
            findings_file=Path("tests/fixtures/findings/all-analysis-states.json"),
        )
    except (SbomError, LocalFindingsError, VexRenderError) as exc:
        raise SystemExit(f"generation failed: {exc}") from exc

    try:
        report = result.execution_report()
        serialized_report = report.to_json()
        if parse_generation_execution_report(serialized_report) != report:
            raise SystemExit("execution report did not round-trip through its parser")
    except GenerationReportMetadataError as exc:
        raise SystemExit(f"package metadata cannot identify the report: {exc}") from exc
    except GenerationExecutionReportParseError as exc:
        raise SystemExit(f"generated execution report is invalid: {exc}") from exc
    except ValueError as exc:
        raise SystemExit(f"generation facts cannot produce a report: {exc}") from exc

    output_directory.mkdir(mode=0o700)
    if os.name != "nt":
        output_directory.chmod(0o700)
    document_path = output_directory / "vex.json"
    report_path = output_directory / "execution-report.json"
    _write_new_private_file(document_path, result.rendered_bytes)
    _write_new_private_file(
        report_path,
        serialized_report.encode("utf-8"),
    )
    print(f"wrote {document_path} and {report_path}")


def _output_directory() -> Path:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_directory", type=Path)
    return parser.parse_args().output_directory


if __name__ == "__main__":
    main(_output_directory())
