"""Check the installed-distribution execution-report contract on Windows."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures"


def main() -> None:
    """Require installed Windows generation to fail closed only for reports."""
    if os.name != "nt":
        raise SystemExit("this installed-distribution check must run on Windows")

    import vexcalibur

    expected_python = os.environ.get("VEXCALIBUR_EXPECTED_PYTHON")
    actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if expected_python is None or actual_python != expected_python:
        raise SystemExit(
            f"installed check uses Python {actual_python}, expected {expected_python!r}"
        )
    expected_version = os.environ.get("VEXCALIBUR_EXPECTED_VERSION")
    actual_version = importlib.metadata.version("vexcalibur")
    if expected_version is None or actual_version != expected_version:
        raise SystemExit(
            f"installed Vexcalibur version is {actual_version}, expected {expected_version!r}"
        )

    package_path = Path(vexcalibur.__file__).resolve()
    if not package_path.is_relative_to(Path(sys.prefix).resolve()):
        raise SystemExit(f"Vexcalibur imported outside the installed environment: {package_path}")

    executable = Path(sys.prefix) / "Scripts" / "vexcalibur.exe"
    if not executable.is_file():
        raise SystemExit(f"installed console script was not found: {executable}")

    with TemporaryDirectory(prefix="vexcalibur-installed-windows-") as directory:
        output_path = Path(directory) / "vex.json"
        report_path = Path(directory) / "execution-report.json"
        stale_report = b'{"stale":true}\n'
        report_path.write_bytes(stale_report)
        base_command = [
            str(executable),
            "generate",
            str(FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FIXTURE_ROOT / "findings" / "all-analysis-states.json"),
            "--offline",
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--output",
            str(output_path),
        ]

        rejected = _run([*base_command, "--execution-report", str(report_path)])
        if rejected.returncode != 1:
            _fail("execution-report request did not fail closed", rejected)
        if output_path.exists() or report_path.read_bytes() != stale_report:
            _fail("failed report request changed an output destination", rejected)
        rejected_output = f"{rejected.stdout}\n{rejected.stderr}"
        if "not supported on Windows" not in rejected_output:
            _fail("failed report request omitted the Windows diagnostic", rejected)
        if "Traceback" in rejected_output:
            _fail("failed report request emitted a traceback", rejected)

        malformed_sbom = Path(directory) / "malformed-sbom.json"
        malformed_findings = Path(directory) / "malformed-findings.json"
        malformed_sbom.write_bytes(b"not an SBOM")
        malformed_findings.write_bytes(b"not findings")
        rejected_malformed = _run(
            [
                str(executable),
                "generate",
                str(malformed_sbom),
                "--findings-file",
                str(malformed_findings),
                "--offline",
                "--output",
                str(output_path),
                "--execution-report",
                str(report_path),
            ]
        )
        if rejected_malformed.returncode != 1:
            _fail("malformed inputs bypassed the Windows report rejection", rejected_malformed)
        if output_path.exists() or report_path.read_bytes() != stale_report:
            _fail("Windows report rejection read or changed malformed inputs", rejected_malformed)
        malformed_output = f"{rejected_malformed.stdout}\n{rejected_malformed.stderr}"
        if "not supported on Windows" not in malformed_output:
            _fail("malformed-input rejection omitted the Windows diagnostic", rejected_malformed)

        generated = _run(base_command)
        if generated.returncode != 0:
            _fail("ordinary installed-distribution generation failed", generated)
        if not output_path.read_text(encoding="utf-8").startswith("{"):
            _fail("ordinary generation did not produce VEX", generated)

        verify_python_api_report()


def verify_python_api_report() -> None:
    """Verify the cross-platform Python API report oracle."""
    from vexcalibur.api import (
        generate_vex_from_local_findings_result,
        parse_generation_execution_report,
    )

    api_result = generate_vex_from_local_findings_result(
        input_file=FIXTURE_ROOT / "sbom" / "cyclonedx-json-simple.json",
        findings_file=FIXTURE_ROOT / "findings" / "all-analysis-states.json",
        timestamp=datetime(2026, 6, 23, tzinfo=timezone.utc),
    )
    report_value = api_result.execution_report()
    parsed_report = parse_generation_execution_report(report_value.to_json())
    if parsed_report != report_value:
        raise SystemExit("installed Python API report did not round-trip through its parser")
    report = parsed_report.to_dict()
    document_bytes = api_result.rendered_bytes
    expected_counts = {
        "exploitable": 1,
        "false_positive": 1,
        "in_triage": 1,
        "not_affected": 1,
        "resolved": 1,
    }
    expected_document = {
        "sha256": hashlib.sha256(document_bytes).hexdigest(),
        "bytes": len(document_bytes),
    }
    if report != {
        "schema_version": 1,
        "command": "generate",
        "vexcalibur_version": importlib.metadata.version("vexcalibur"),
        "inventory_source": "sbom_file",
        "finding_source": "local_file",
        "output_format": "cyclonedx",
        "component_count": 2,
        "finding_count": 5,
        "analysis_state_counts": expected_counts,
        "document": expected_document,
    }:
        raise SystemExit(
            "installed Python API produced an unexpected execution report:\n"
            f"{json.dumps(report, indent=2, sort_keys=True)}"
        )


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - commands are built by this test harness.
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _fail(message: str, result: subprocess.CompletedProcess[str]) -> None:
    print(message, file=sys.stderr)
    print(result.stdout, file=sys.stderr)
    print(result.stderr, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
