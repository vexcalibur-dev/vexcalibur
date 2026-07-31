from __future__ import annotations

import importlib.metadata
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import vexcalibur.execution_report_destination as destination_module
from vexcalibur import cli
from vexcalibur.execution_report_destination import BoundFileDestinationError

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
FINDINGS_ROOT = Path(__file__).parent / "fixtures" / "findings"


@pytest.mark.skipif(os.name == "nt", reason="Bash completion contract")
def test_shell_completion_does_not_prepare_execution_report(tmp_path: Path) -> None:
    report_path = tmp_path / "execution-report.json"
    stale = b'{"stale":true}\n'
    report_path.write_bytes(stale)
    environment = {
        **os.environ,
        "COMP_WORDS": (
            "vexcalibur generate tests/fixtures/sbom/cyclonedx-json-simple.json "
            f"--execution-report {report_path} --f"
        ),
        "COMP_CWORD": "5",
        "_VEXCALIBUR_COMPLETE": "complete_bash",
    }

    executable = Path(sys.executable).with_name("vexcalibur")
    assert executable.is_file()
    completed = subprocess.run(  # noqa: S603
        [executable],
        cwd=Path(__file__).parents[1],
        env=environment,
        check=False,
        capture_output=True,
    )

    assert completed.returncode == 0
    assert b"--findings-file" in completed.stdout or b"--format" in completed.stdout
    assert report_path.read_bytes() == stale


def test_malformed_options_cannot_delete_a_possible_input(tmp_path: Path) -> None:
    input_path = tmp_path / "inventory.json"
    original = (FIXTURE_ROOT / "cyclonedx-json-simple.json").read_bytes()
    input_path.write_bytes(original)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--unknown-option",
            "value",
            str(input_path),
            "--execution-report",
            str(input_path),
        ],
    )

    assert result.exit_code != 0
    assert input_path.read_bytes() == original


def test_execution_report_parent_failure_happens_before_generation(tmp_path: Path) -> None:
    report_path = tmp_path / "missing" / "execution-report.json"
    output_path = tmp_path / "vex.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert not output_path.exists()
    assert not report_path.exists()
    assert "execution report parent directory does not exist" in result.output
    assert "Traceback" not in result.output


def test_vex_output_parent_failure_names_the_vex_destination(tmp_path: Path) -> None:
    output_path = tmp_path / "missing" / "vex.json"
    report_path = tmp_path / "execution-report.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert not output_path.exists()
    assert not report_path.exists()
    assert "VEX output parent directory does not exist" in result.output
    assert "execution report parent directory does not exist" not in result.output


def test_binary_standard_output_is_optional_for_text_only_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.sys, "stdout", io.StringIO())

    assert cli._binary_standard_output() is None


def test_generation_without_report_does_not_inspect_binary_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_standard_output_access() -> None:
        raise AssertionError("ordinary generation must not inspect binary stdout")

    monkeypatch.setattr(
        cli,
        "_standard_output_descriptor",
        unexpected_standard_output_access,
    )
    monkeypatch.setattr(
        cli,
        "_binary_standard_output",
        unexpected_standard_output_access,
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--timestamp",
            "2026-06-23T00:00:00Z",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"bomFormat": "CycloneDX"' in result.output


def test_missing_package_metadata_prevents_all_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def missing_version(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        missing_version,
    )
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert not output_path.exists()
    assert not report_path.exists()
    assert "Could not create execution report" in result.output
    assert "package metadata is unavailable" in result.output


@pytest.mark.parametrize(
    "metadata_error",
    (
        OSError("package metadata cannot be read"),
        UnicodeError("package metadata cannot be decoded"),
    ),
)
def test_package_metadata_read_failure_prevents_all_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    metadata_error: Exception,
) -> None:
    def fail_version(name: str) -> str:
        raise metadata_error

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        fail_version,
    )
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert not output_path.exists()
    assert not report_path.exists()
    assert "Could not create execution report" in result.output
    assert "package metadata is unavailable" in result.output


def test_missing_package_metadata_does_not_affect_generation_without_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def missing_version(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        missing_version,
    )
    output_path = tmp_path / "vex.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.read_text(encoding="utf-8").startswith("{")
    assert "package metadata" not in result.output


def test_source_checkout_identity_is_not_required_without_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def unexpected_source_identity_check(version: str) -> None:
        raise AssertionError(f"ordinary generation inspected source identity for {version}")

    monkeypatch.setattr(
        "vexcalibur.generation_result.verify_source_checkout_version",
        unexpected_source_identity_check,
    )
    output_path = tmp_path / "vex.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.read_text(encoding="utf-8").startswith("{")


def test_report_commit_failure_occurs_after_vex_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_commit = destination_module.StagedFileWrite.commit

    def fail_report_commit(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        if staged.destination.requested_path == report_path:
            raise BoundFileDestinationError("report replace failed")
        real_commit(staged, destination_lock_held=destination_lock_held)

    monkeypatch.setattr(destination_module.StagedFileWrite, "commit", fail_report_commit)

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(FINDINGS_ROOT / "all-analysis-states.json"),
            "--offline",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert output_path.read_text(encoding="utf-8").startswith("{")
    assert not report_path.exists()
    assert "Could not write execution report" in result.output
    assert "report replace failed" in result.output


def test_invalid_vex_output_leaf_leaves_no_execution_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--output",
            str(tmp_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert not report_path.exists()
    assert "Could not prepare generate outputs: VEX output" in result.output
    assert "regular file" in result.output


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor alias contract")
def test_redirected_stdout_cannot_be_replaced_by_execution_report(tmp_path: Path) -> None:
    report_path = tmp_path / "redirected-output.json"
    stale = b'{"stale":true}\n'
    report_path.write_bytes(stale)

    with report_path.open("r+b") as redirected_stdout:
        completed = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "vexcalibur.cli",
                "generate",
                str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
                "--findings-file",
                str(FINDINGS_ROOT / "all-analysis-states.json"),
                "--offline",
                "--execution-report",
                str(report_path),
            ],
            cwd=Path(__file__).parents[1],
            check=False,
            stdout=redirected_stdout,
            stderr=subprocess.PIPE,
        )

    assert completed.returncode == 1
    assert report_path.read_bytes() == stale
    assert b"must not replace redirected standard output" in completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor alias contract")
def test_redirected_stdout_is_protected_with_file_output(tmp_path: Path) -> None:
    report_path = tmp_path / "redirected-output.json"
    output_path = tmp_path / "vex.json"
    stale = b'{"stale":true}\n'
    report_path.write_bytes(stale)

    with report_path.open("r+b") as redirected_stdout:
        completed = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "vexcalibur.cli",
                "generate",
                str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
                "--findings-file",
                str(FINDINGS_ROOT / "all-analysis-states.json"),
                "--offline",
                "--output",
                str(output_path),
                "--execution-report",
                str(report_path),
            ],
            cwd=Path(__file__).parents[1],
            check=False,
            stdout=redirected_stdout,
            stderr=subprocess.PIPE,
        )

    assert completed.returncode == 1
    assert report_path.read_bytes() == stale
    assert not output_path.exists()
    assert b"must not replace redirected standard output" in completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor alias contract")
def test_redirected_stderr_cannot_be_replaced_by_execution_report(tmp_path: Path) -> None:
    report_path = tmp_path / "redirected-error.log"
    stale = b"existing diagnostic\n"
    report_path.write_bytes(stale)

    with report_path.open("ab") as redirected_stderr:
        completed = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "vexcalibur.cli",
                "generate",
                str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
                "--findings-file",
                str(FINDINGS_ROOT / "all-analysis-states.json"),
                "--offline",
                "--execution-report",
                str(report_path),
            ],
            cwd=Path(__file__).parents[1],
            check=False,
            stdout=subprocess.PIPE,
            stderr=redirected_stderr,
        )

    content = report_path.read_bytes()
    assert completed.returncode == 1
    assert content.startswith(stale)
    assert b"must not replace redirected standard error" in content


def test_execution_report_rejects_input_and_output_path_collisions(
    tmp_path: Path,
) -> None:
    input_path = FIXTURE_ROOT / "cyclonedx-json-simple.json"
    output_path = tmp_path / "vex.json"
    findings_path = FINDINGS_ROOT / "all-analysis-states.json"

    for protected_path, extra_args in (
        (input_path, []),
        (output_path, ["--output", str(output_path)]),
        (
            findings_path,
            [
                "--findings-file",
                str(findings_path),
                "--offline",
            ],
        ),
    ):
        result = runner.invoke(
            cli.app,
            [
                "generate",
                str(input_path),
                *extra_args,
                "--execution-report",
                str(protected_path),
            ],
        )

        assert result.exit_code == 1
        assert "must not replace an input or VEX output file" in result.output
        assert "Traceback" not in result.output


@pytest.mark.skipif(os.name != "nt", reason="native Windows CLI contract")
def test_native_windows_cli_fails_closed_for_report_and_keeps_normal_output(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    output_path = tmp_path / "vex.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")
    base_arguments = [
        "generate",
        str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        "--findings-file",
        str(FINDINGS_ROOT / "all-analysis-states.json"),
        "--offline",
        "--output",
        str(output_path),
    ]

    rejected = runner.invoke(
        cli.app,
        [*base_arguments, "--execution-report", str(report_path)],
    )

    assert rejected.exit_code == 1
    assert not output_path.exists()
    assert report_path.read_text(encoding="utf-8") == '{"stale":true}\n'
    assert "not supported on Windows" in rejected.output
    assert "Traceback" not in rejected.output

    generated = runner.invoke(cli.app, base_arguments)

    assert generated.exit_code == 0, generated.output
    assert output_path.read_text(encoding="utf-8").startswith("{")
