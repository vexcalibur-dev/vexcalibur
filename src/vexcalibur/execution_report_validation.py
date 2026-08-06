"""Independent validation for generated documents and execution reports."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path

from vexcalibur.execution_report_filesystem import (
    _close_descriptor,
    _defer_keyboard_interrupt,
)
from vexcalibur.generation_context import ExecutionReportOutputFormat
from vexcalibur.generation_result import (
    MAX_EXECUTION_REPORT_BYTES,
    MAX_GENERATED_DOCUMENT_BYTES,
    GenerationExecutionReportParseError,
    parse_generation_execution_report,
)

_VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.!+_-]{0,127}", re.ASCII)
_DOCUMENT_NAMES = {
    ExecutionReportOutputFormat.CYCLONEDX: (
        "vex.cdx.json",
        "vex.cdx.execution.json",
    ),
    ExecutionReportOutputFormat.OPENVEX: (
        "vex.openvex.json",
        "vex.openvex.execution.json",
    ),
    ExecutionReportOutputFormat.CSAF: (
        "vexcalibur-vex.json",
        "vexcalibur-vex.execution.json",
    ),
}


class ExecutionReportValidationError(ValueError):
    """Raised when a generated document and report violate their contract."""


def _require_nonnegative_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ExecutionReportValidationError(f"{field} must be a nonnegative integer")
    return value


def _read_regular_file(path: Path, *, maximum_bytes: int, field: str) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = -1
    try:
        try:
            with _defer_keyboard_interrupt():
                descriptor = os.open(path, flags)
        except OSError as exc:
            raise ExecutionReportValidationError(f"cannot open {field}: {exc}") from exc
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ExecutionReportValidationError(f"{field} must be a regular file")
        if before.st_size > maximum_bytes:
            raise ExecutionReportValidationError(f"{field} exceeds the {maximum_bytes} byte limit")

        content = bytearray()
        while len(content) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
    except OSError as exc:
        raise ExecutionReportValidationError(f"cannot read {field}: {exc}") from exc
    finally:
        _close_descriptor(descriptor)

    if len(content) > maximum_bytes:
        raise ExecutionReportValidationError(f"{field} exceeds the {maximum_bytes} byte limit")
    snapshots = (before, after, path_metadata)
    if any(not stat.S_ISREG(metadata.st_mode) for metadata in snapshots):
        raise ExecutionReportValidationError(f"{field} must be a regular file")
    identity = (before.st_dev, before.st_ino)
    if any((metadata.st_dev, metadata.st_ino) != identity for metadata in snapshots[1:]):
        raise ExecutionReportValidationError(f"{field} changed while it was read")
    if any(
        (
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        != (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        for metadata in snapshots[1:]
    ):
        raise ExecutionReportValidationError(f"{field} changed while it was read")
    if len(content) != before.st_size:
        raise ExecutionReportValidationError(f"{field} changed while it was read")
    return bytes(content)


def validate_execution_reports(
    output_dir: Path,
    *,
    formats: tuple[ExecutionReportOutputFormat, ...],
    expected_version: str,
    expected_finding_count: int,
    expected_component_count: int | None = None,
) -> None:
    """Validate canonical reports and their exact generated-document bindings."""
    if any(type(output_format) is not ExecutionReportOutputFormat for output_format in formats):
        raise ExecutionReportValidationError("formats contain an unsupported output format")
    if not formats or len(set(formats)) != len(formats):
        raise ExecutionReportValidationError("formats must be unique and nonempty")
    if any(output_format not in _DOCUMENT_NAMES for output_format in formats):
        raise ExecutionReportValidationError("formats contain an unsupported output format")
    if _VERSION_PATTERN.fullmatch(expected_version) is None:
        raise ExecutionReportValidationError("expected version is invalid")
    _require_nonnegative_integer(
        expected_finding_count,
        field="expected finding count",
    )
    if expected_component_count is not None:
        _require_nonnegative_integer(
            expected_component_count,
            field="expected component count",
        )

    for output_format in formats:
        document_name, report_name = _DOCUMENT_NAMES[output_format]
        document = _read_regular_file(
            output_dir / document_name,
            maximum_bytes=MAX_GENERATED_DOCUMENT_BYTES,
            field=f"{output_format.value} document",
        )
        report_bytes = _read_regular_file(
            output_dir / report_name,
            maximum_bytes=MAX_EXECUTION_REPORT_BYTES,
            field=f"{output_format.value} execution report",
        )
        try:
            report = parse_generation_execution_report(report_bytes)
        except GenerationExecutionReportParseError as exc:
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report is invalid: {exc}"
            ) from exc
        if report.vexcalibur_version != expected_version:
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report version is invalid"
            )
        if report.inventory_source.value != "sbom_file":
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report inventory source is invalid"
            )
        if report.finding_source.value != "local_file":
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report finding source is invalid"
            )
        if report.output_format is not output_format:
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report output format is invalid"
            )

        component_count = report.component_count
        if expected_component_count is None:
            if component_count == 0:
                raise ExecutionReportValidationError(
                    f"{output_format.value} execution report component count is invalid"
                )
        elif component_count != expected_component_count:
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report component count is invalid"
            )

        finding_count = report.finding_count
        if finding_count != expected_finding_count:
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report finding count is invalid"
            )
        if (
            report.document.bytes != len(document)
            or report.document.sha256 != hashlib.sha256(document).hexdigest()
        ):
            raise ExecutionReportValidationError(
                f"{output_format.value} execution report document binding is invalid"
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate Vexcalibur documents and execution reports.",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--finding-count", type=int, required=True)
    parser.add_argument("--component-count", type=int)
    parser.add_argument(
        "--format",
        action="append",
        choices=tuple(output_format.value for output_format in _DOCUMENT_NAMES),
        dest="formats",
        required=True,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the installed validation command."""
    args = _parser().parse_args(argv)
    try:
        validate_execution_reports(
            args.output_dir,
            formats=tuple(ExecutionReportOutputFormat(value) for value in args.formats),
            expected_version=args.release_version,
            expected_finding_count=args.finding_count,
            expected_component_count=args.component_count,
        )
    except ExecutionReportValidationError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
