"""Independent execution-report validation for release publication."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol


class ExecutionReportOracleError(ValueError):
    """Raised when release evidence contains an invalid execution report."""


class _ValidationError(Protocol):
    absolute_path: Iterable[object]
    message: str


class ReportSchemaValidator(Protocol):
    """Structural validator used by the independent publication oracle."""

    def iter_errors(self, instance: object) -> Iterable[_ValidationError]:
        """Return schema errors for one report candidate."""


def canonical_execution_report_json(document: object) -> str:
    """Serialize one report according to the public canonical byte contract."""
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def execution_report_schema_validator(schema_path: Path) -> ReportSchemaValidator:
    """Load and validate the checked-in report schema."""
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
    except ImportError as exc:
        raise ExecutionReportOracleError(
            "execution report publication validation requires the locked jsonschema dependency"
        ) from exc

    try:
        schema = json.loads(
            schema_path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionReportOracleError(f"could not load execution report schema: {exc}") from exc
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ExecutionReportOracleError(
            f"execution report schema is invalid: {exc.message}"
        ) from exc
    return Draft202012Validator(schema)


def validate_execution_report_document(
    document: object,
    *,
    validator: ReportSchemaValidator,
) -> dict[str, object]:
    """Validate schema and cross-field integer invariants."""
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "report"
        raise ExecutionReportOracleError(
            f"execution report schema violation at {location}: {first.message}"
        )
    report = _require_dict(document, field="execution report")
    state_counts = _require_dict(
        report.get("analysis_state_counts"),
        field="execution report analysis_state_counts",
    )
    for field in ("schema_version", "component_count", "finding_count"):
        if type(report.get(field)) is not int:
            raise ExecutionReportOracleError(f"execution report {field} must be an integer")
    document_metadata = _require_dict(
        report.get("document"),
        field="execution report document",
    )
    if type(document_metadata.get("bytes")) is not int:
        raise ExecutionReportOracleError("execution report document bytes must be an integer")
    counts: list[int] = []
    for count in state_counts.values():
        if type(count) is not int:
            raise ExecutionReportOracleError(
                "execution report analysis-state counts must be integers"
            )
        counts.append(count)
    if sum(counts) != report.get("finding_count"):
        raise ExecutionReportOracleError(
            "execution report analysis-state counts do not sum to finding count"
        )
    return report


def load_execution_report(
    path: Path,
    *,
    validator: ReportSchemaValidator,
    max_bytes: int,
) -> dict[str, object]:
    """Read one bounded canonical report and validate it independently."""
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExecutionReportOracleError(f"could not open execution report {path}: {exc}") from exc
    try:
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            raise ExecutionReportOracleError(
                f"expected a regular, non-symlink execution report: {path}"
            )
        if file_status.st_size > max_bytes:
            raise ExecutionReportOracleError(
                f"execution report exceeds the {max_bytes} byte limit: {path}"
            )
        raw = _read_bounded(descriptor, max_bytes=max_bytes)
    except OSError as exc:
        raise ExecutionReportOracleError(f"could not read execution report {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if len(raw) > max_bytes:
        raise ExecutionReportOracleError(
            f"execution report exceeds the {max_bytes} byte limit: {path}"
        )
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExecutionReportOracleError(
            f"execution report is not valid UTF-8 JSON: {path}: {exc}"
        ) from exc
    if raw != canonical_execution_report_json(document).encode("ascii"):
        raise ExecutionReportOracleError(f"execution report is not canonical JSON: {path}")
    return validate_execution_report_document(document, validator=validator)


def _read_bounded(descriptor: int, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _object_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionReportOracleError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _require_dict(value: object, *, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ExecutionReportOracleError(f"{field} must be an object")
    return value
