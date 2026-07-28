from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vexcalibur.execution_report_validation import (
    ExecutionReportValidationError,
    validate_execution_reports,
)
from vexcalibur.generation_context import ExecutionReportOutputFormat


def _write_report_pair(
    output_dir: Path,
    *,
    output_format: ExecutionReportOutputFormat,
    state_counts: dict[str, int],
) -> None:
    names = {
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
    document_name, report_name = names[output_format]
    document = (
        json.dumps(
            {"format": output_format.value},
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    (output_dir / document_name).write_bytes(document)
    report = {
        "analysis_state_counts": state_counts,
        "command": "generate",
        "component_count": 2,
        "document": {
            "bytes": len(document),
            "sha256": hashlib.sha256(document).hexdigest(),
        },
        "finding_count": sum(state_counts.values()),
        "finding_source": "local_file",
        "inventory_source": "sbom_file",
        "output_format": output_format.value,
        "schema_version": 1,
        "vexcalibur_version": "0.5.0",
    }
    (output_dir / report_name).write_text(
        json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    )


def test_validator_accepts_canonical_multistate_reports_for_every_format(
    tmp_path: Path,
) -> None:
    formats = (
        ExecutionReportOutputFormat.CYCLONEDX,
        ExecutionReportOutputFormat.OPENVEX,
        ExecutionReportOutputFormat.CSAF,
    )
    state_counts = {
        "exploitable": 1,
        "false_positive": 1,
        "in_triage": 1,
        "not_affected": 1,
        "resolved": 1,
    }
    for output_format in formats:
        _write_report_pair(
            tmp_path,
            output_format=output_format,
            state_counts=state_counts,
        )

    validate_execution_reports(
        tmp_path,
        formats=formats,
        expected_version="0.5.0",
        expected_finding_count=5,
        expected_component_count=2,
    )


def test_validator_rejects_noncanonical_report_bytes(tmp_path: Path) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={"in_triage": 1},
    )
    report_path = tmp_path / "vex.cdx.execution.json"
    report = json.loads(report_path.read_bytes())
    report_path.write_text(json.dumps(report, indent=2) + "\n")

    with pytest.raises(ExecutionReportValidationError, match="not canonical JSON"):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=1,
        )


def test_validator_rejects_a_document_digest_mismatch(tmp_path: Path) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={},
    )
    (tmp_path / "vex.cdx.json").write_text('{"changed":true}\n')

    with pytest.raises(ExecutionReportValidationError, match="document binding"):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=0,
        )


def test_validator_rejects_a_symlinked_document(tmp_path: Path) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={},
    )
    document_path = tmp_path / "vex.cdx.json"
    target_path = tmp_path / "document-target.json"
    document_path.rename(target_path)
    document_path.symlink_to(target_path.name)

    with pytest.raises(
        ExecutionReportValidationError,
        match=r"cannot open cyclonedx document|cyclonedx document must be a regular file",
    ):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=0,
        )


def test_validator_rejects_an_unsupported_output_format(tmp_path: Path) -> None:
    with pytest.raises(
        ExecutionReportValidationError,
        match="unsupported output format",
    ):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CUSTOM,),
            expected_version="0.5.0",
            expected_finding_count=0,
        )
