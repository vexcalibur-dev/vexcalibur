from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cli_accepts_non_utf8_posix_output_filenames(tmp_path: Path) -> None:
    fixture_root = Path(__file__).parent / "fixtures"
    probe_path = os.fsencode(tmp_path) + b"/probe-\xff"
    try:
        probe_descriptor = os.open(
            probe_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except OSError as exc:
        if exc.errno == errno.EILSEQ:
            pytest.skip("filesystem rejects non-UTF-8 filenames")
        raise
    else:
        os.close(probe_descriptor)
        os.unlink(probe_path)
    output_path = os.fsencode(tmp_path) + b"/vex-\xff.json"
    report_path = os.fsencode(tmp_path) + b"/report-\xfe.json"
    command = [
        os.fsencode(sys.executable),
        b"-c",
        b"from vexcalibur.cli import app; app()",
        b"generate",
        os.fsencode(fixture_root / "sbom" / "cyclonedx-json-simple.json"),
        b"--findings-file",
        os.fsencode(fixture_root / "findings" / "all-analysis-states.json"),
        b"--offline",
        b"--output",
        output_path,
        b"--execution-report",
        report_path,
    ]

    result = subprocess.run(  # noqa: S603 - fixed interpreter and local test fixtures.
        command,
        check=False,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert os.path.isfile(output_path)
    assert os.path.isfile(report_path)
    assert b"Traceback" not in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cli_rejects_parent_directory_as_report_without_traceback(tmp_path: Path) -> None:
    fixture_root = Path(__file__).parent / "fixtures"
    command = [
        sys.executable,
        "-c",
        "from vexcalibur.cli import app; app()",
        "generate",
        str(fixture_root / "sbom" / "cyclonedx-json-simple.json"),
        "--findings-file",
        str(fixture_root / "findings" / "all-analysis-states.json"),
        "--offline",
        "--execution-report",
        "..",
    ]

    result = subprocess.run(  # noqa: S603 - fixed interpreter and local test fixtures.
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 1
    assert "Could not prepare generate outputs: execution report must name a file" in result.stderr
    assert "Traceback" not in result.stderr
