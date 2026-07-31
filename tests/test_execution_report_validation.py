from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

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


def _mutate_report(
    output_dir: Path,
    mutation: Any,
) -> None:
    report_path = output_dir / "vex.cdx.execution.json"
    report = json.loads(report_path.read_bytes())
    mutation(report)
    report_path.write_text(
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


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda report: report.__setitem__("command", "scan"), "invalid"),
        (lambda report: report.__setitem__("vexcalibur_version", "0.4.9"), "version"),
        (
            lambda report: report.__setitem__(
                "inventory_source",
                "github_dependency_graph",
            ),
            "inventory source",
        ),
        (
            lambda report: report.__setitem__("finding_source", "public_osv"),
            "finding source",
        ),
        (lambda report: report.__setitem__("output_format", "openvex"), "output format"),
        (lambda report: report.__setitem__("component_count", True), "invalid"),
        (lambda report: report.__setitem__("finding_count", -1), "invalid"),
        (
            lambda report: report["analysis_state_counts"].__setitem__("in_triage", 0),
            "invalid",
        ),
        (lambda report: report.__setitem__("unexpected", True), "unexpected fields"),
        (lambda report: report.pop("command"), "unexpected fields"),
        (
            lambda report: report["document"].__setitem__("unexpected", True),
            "unexpected fields",
        ),
    ),
)
def test_validator_rejects_contract_and_release_policy_mutations(
    mutation: Any,
    message: str,
    tmp_path: Path,
) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={"in_triage": 1},
    )
    _mutate_report(tmp_path, mutation)

    with pytest.raises(ExecutionReportValidationError, match=message):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=1,
        )


def test_validator_rejects_duplicate_report_keys(tmp_path: Path) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={},
    )
    report_path = tmp_path / "vex.cdx.execution.json"
    report_path.write_text(
        report_path.read_text().replace(
            '"command":"generate",',
            '"command":"generate","command":"generate",',
        )
    )

    with pytest.raises(ExecutionReportValidationError, match="duplicate"):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=0,
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


@pytest.mark.parametrize(
    ("file_name", "maximum_bytes"),
    (
        ("vex.cdx.json", 25 * 1024 * 1024),
        ("vex.cdx.execution.json", 16 * 1024),
    ),
)
def test_validator_rejects_oversized_files(
    file_name: str,
    maximum_bytes: int,
    tmp_path: Path,
) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={},
    )
    (tmp_path / file_name).write_bytes(b"x" * (maximum_bytes + 1))

    with pytest.raises(ExecutionReportValidationError, match="exceeds"):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=0,
        )


@pytest.mark.parametrize("file_name", ("vex.cdx.json", "vex.cdx.execution.json"))
def test_validator_rejects_a_path_replaced_while_reading(
    file_name: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={},
    )
    selected_path = tmp_path / file_name
    selected_stat = selected_path.stat()
    selected_identity = (selected_stat.st_dev, selected_stat.st_ino)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        content = original_read(descriptor, size)
        descriptor_stat = os.fstat(descriptor)
        if (
            not replaced
            and content
            and (descriptor_stat.st_dev, descriptor_stat.st_ino) == selected_identity
        ):
            replaced = True
            moved = selected_path.with_suffix(f"{selected_path.suffix}.moved")
            selected_path.rename(moved)
            selected_path.write_bytes(content)
        return content

    monkeypatch.setattr(
        "vexcalibur.execution_report_validation.os.read",
        replace_after_read,
    )

    with pytest.raises(ExecutionReportValidationError, match="changed while it was read"):
        validate_execution_reports(
            tmp_path,
            formats=(ExecutionReportOutputFormat.CYCLONEDX,),
            expected_version="0.5.0",
            expected_finding_count=0,
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
@pytest.mark.parametrize("fifo_name", ["vex.cdx.json", "vex.cdx.execution.json"])
def test_validator_rejects_a_fifo_without_blocking(
    tmp_path: Path,
    fifo_name: str,
) -> None:
    _write_report_pair(
        tmp_path,
        output_format=ExecutionReportOutputFormat.CYCLONEDX,
        state_counts={},
    )
    fifo_path = tmp_path / fifo_name
    fifo_path.unlink()
    os.mkfifo(fifo_path)

    with pytest.raises(ExecutionReportValidationError, match="must be a regular file"):
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


def test_validator_rejects_a_string_output_format_cleanly(tmp_path: Path) -> None:
    with pytest.raises(
        ExecutionReportValidationError,
        match="unsupported output format",
    ):
        validate_execution_reports(
            tmp_path,
            formats=("cyclonedx",),  # type: ignore[arg-type]
            expected_version="0.5.0",
            expected_finding_count=0,
        )
