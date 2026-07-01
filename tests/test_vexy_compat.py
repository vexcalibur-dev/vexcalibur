import json
import shlex
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import vexcalibur.sources.osv as osv_module
from vexcalibur.compat import vexy

ROOT = Path(__file__).parent.parent
FIXTURE_ROOT = ROOT / "tests" / "fixtures"
GOLDEN_ROOT = ROOT / "tests" / "golden"
LEGACY_CONFIG = FIXTURE_ROOT / "vexy" / "legacy-config.yml"
LEGACY_SBOM = FIXTURE_ROOT / "sbom" / "cyclonedx-xml-1.5-simple.xml"
JSON_SBOM = FIXTURE_ROOT / "sbom" / "cyclonedx-json-1.5-simple.json"
FINDINGS_FILE = FIXTURE_ROOT / "findings" / "all-analysis-states.json"
TIMESTAMP = "2026-06-23T00:00:00Z"
STABLE_HELP_ENV = {"COLUMNS": "120", "NO_COLOR": "1", "TERM": "dumb"}

runner = CliRunner()


def test_vexy_compat_help_matches_golden_expectations() -> None:
    expected = _golden_case("help")

    result = runner.invoke(vexy.app, ["--help"], env=STABLE_HELP_ENV)

    assert result.exit_code == expected["exit_code"]
    for expected_stdout in expected["stdout_contains"]:
        assert expected_stdout in result.stdout
    assert result.stderr == expected["stderr"]
    assert "Traceback" not in _combined_output(result)


def test_vexy_compat_generates_golden_stdout_from_legacy_input() -> None:
    _assert_cli_result(
        result=runner.invoke(vexy.app, _offline_stdout_args()),
        expected=_golden_case("offline_stdout"),
    )


def test_vexy_compat_generates_golden_stdout_from_json_input() -> None:
    _assert_cli_result(
        result=runner.invoke(vexy.app, _offline_stdout_args(input_path=JSON_SBOM)),
        expected=_golden_case("json_stdout"),
    )


def test_vexy_compat_debug_output_uses_stderr_without_corrupting_stdout() -> None:
    _assert_cli_result(
        result=runner.invoke(vexy.app, [*_offline_stdout_args(), "-X"]),
        expected=_golden_case("debug_stdout"),
    )


@pytest.mark.parametrize(
    ("extra_args", "golden_case"),
    (
        (["--format", "xml"], "unsupported_xml_format"),
        (["--schema-version", "1.4"], "unsupported_schema_1_4"),
    ),
)
def test_vexy_compat_rejects_unsupported_legacy_output_modes(
    extra_args: list[str],
    golden_case: str,
) -> None:
    result = runner.invoke(
        vexy.app,
        [
            "-i",
            str(LEGACY_SBOM),
            "--output",
            "-",
            "--offline",
            "--findings-file",
            str(FINDINGS_FILE),
            *extra_args,
        ],
    )

    _assert_cli_result(result=result, expected=_golden_case(golden_case))


def test_vexy_compat_rejects_legacy_stdin_input_explicitly() -> None:
    result = runner.invoke(
        vexy.app,
        [
            "-i",
            "-",
            "--output",
            "-",
            "--offline",
            "--findings-file",
            str(FINDINGS_FILE),
        ],
    )

    _assert_cli_result(result=result, expected=_golden_case("unsupported_stdin"))


@pytest.mark.parametrize(
    ("args", "golden_case"),
    (
        (["--format", "json", "--output", "-"], "missing_input"),
        (["-i", str(LEGACY_SBOM), "--output", "-", "--offline"], "offline_without_findings"),
        (["-i", str(LEGACY_SBOM), "--output", "-", "--osv-url", ""], "empty_osv_url"),
        (
            [
                "-i",
                str(LEGACY_SBOM),
                "--output",
                "-",
                "--findings-file",
                str(FINDINGS_FILE),
                "--allow-public-osv",
            ],
            "findings_with_public_osv",
        ),
        (
            [
                "-i",
                str(LEGACY_SBOM),
                "--output",
                "-",
                "--findings-file",
                str(FINDINGS_FILE),
                "--osv-url",
                "https://osv.internal.example",
            ],
            "findings_with_osv_url",
        ),
        (
            [
                "-i",
                str(LEGACY_SBOM),
                "--output",
                "-",
                "--offline",
                "--findings-file",
                str(FINDINGS_FILE),
                "--timestamp",
                "not a timestamp",
            ],
            "invalid_timestamp",
        ),
    ),
)
def test_vexy_compat_reports_source_and_parameter_errors_from_golden(
    args: list[str],
    golden_case: str,
) -> None:
    result = runner.invoke(vexy.app, args)

    _assert_cli_result(result=result, expected=_golden_case(golden_case))


def test_vexy_compat_preserves_public_osv_opt_in_boundary() -> None:
    result = runner.invoke(vexy.app, _public_osv_args())

    _assert_cli_result(result=result, expected=_golden_case("requires_public_osv_opt_in"))


def test_vexy_compat_rejects_whitespace_padded_public_osv_without_opt_in() -> None:
    result = runner.invoke(
        vexy.app,
        [*_public_osv_args(), "--osv-url", " https://api.osv.dev "],
    )

    _assert_cli_result(result=result, expected=_golden_case("requires_public_osv_opt_in"))


def test_vexy_compat_preflights_existing_output_before_osv(monkeypatch, tmp_path: Path) -> None:
    class FakeOsvClient:
        def __init__(self, **kwargs) -> None:
            raise AssertionError("OSV client should not be constructed for a doomed output path")

    monkeypatch.setattr(osv_module, "OsvClient", FakeOsvClient)
    output_path = tmp_path / "vex.json"
    output_path.write_text("existing\n", encoding="utf-8")

    result = runner.invoke(
        vexy.app,
        [
            "-i",
            str(LEGACY_SBOM),
            "--format",
            "json",
            "--schema-version",
            "1.6",
            "--output",
            str(output_path),
            "--allow-public-osv",
        ],
    )

    _assert_cli_result(result=result, expected=_golden_case("output_exists_without_force"))
    assert output_path.read_text(encoding="utf-8") == "existing\n"


def test_vexy_compat_requires_force_before_overwriting_output_file(tmp_path: Path) -> None:
    output_path = tmp_path / "vex.json"
    output_path.write_text("existing\n", encoding="utf-8")

    result = runner.invoke(
        vexy.app,
        [*_offline_stdout_args(output_path=output_path), "--force"],
    )
    _assert_cli_result(result=result, expected=_golden_case("output_with_force"))
    assert output_path.read_text(encoding="utf-8") == _read_golden_stdout("output_with_force")

    output_path.write_text("existing\n", encoding="utf-8")
    result = runner.invoke(vexy.app, _offline_stdout_args(output_path=output_path))
    _assert_cli_result(result=result, expected=_golden_case("output_exists_without_force"))
    assert output_path.read_text(encoding="utf-8") == "existing\n"


@pytest.mark.parametrize("output_option", ("-o", "--o", "--output"))
def test_vexy_compat_output_aliases_write_golden_file(
    output_option: str,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"

    result = runner.invoke(
        vexy.app,
        _offline_stdout_args(output_option=output_option, output_path=output_path),
    )

    _assert_cli_result(result=result, expected=_golden_case("output_with_force"))
    assert output_path.read_text(encoding="utf-8") == _read_golden_stdout("output_with_force")


def test_vexy_compat_default_output_writes_legacy_filename(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        vexy.app,
        _offline_stdout_args(output_option=None, output_path=None),
    )
    output_path = tmp_path / "cyclonedx-vex.json"

    _assert_cli_result(result=result, expected=_golden_case("default_output"))
    assert output_path.read_text(encoding="utf-8") == _read_golden_stdout("default_output")


def test_documented_vexy_compat_offline_example_executes() -> None:
    args = _documented_vexy_args("vexy-compat-offline-example")

    result = runner.invoke(vexy.app, args)

    _assert_cli_result(result=result, expected=_golden_case("offline_stdout"))


def _offline_stdout_args(
    *,
    input_path: Path = LEGACY_SBOM,
    output_option: str | None = "--output",
    output_path: Path | None = None,
) -> list[str]:
    args = [
        "-c",
        str(LEGACY_CONFIG),
        "-i",
        str(input_path),
        "--format",
        "json",
        "--schema-version",
        "1.6",
        "--offline",
        "--findings-file",
        str(FINDINGS_FILE),
        "--timestamp",
        TIMESTAMP,
    ]
    if output_option is not None:
        args[8:8] = [output_option, "-" if output_path is None else str(output_path)]
    return args


def _public_osv_args() -> list[str]:
    return [
        "-c",
        str(LEGACY_CONFIG),
        "-i",
        str(LEGACY_SBOM),
        "--format",
        "json",
        "--schema-version",
        "1.6",
        "--output",
        "-",
    ]


def _assert_cli_result(*, result, expected: dict[str, Any]) -> None:
    assert result.exit_code == expected["exit_code"]

    if "stdout" in expected:
        assert result.stdout == expected["stdout"]
    if "stdout_file" in expected:
        assert result.stdout == (GOLDEN_ROOT / expected["stdout_file"]).read_text(encoding="utf-8")
    if "stderr" in expected:
        assert result.stderr == expected["stderr"]
    for expected_stderr in expected.get("stderr_contains", []):
        assert expected_stderr in result.stderr

    assert "Traceback" not in _combined_output(result)


def _combined_output(result) -> str:
    return f"{result.stdout}\n{result.stderr}"


def _golden_case(case_name: str) -> dict[str, Any]:
    golden = json.loads((GOLDEN_ROOT / "vexy-compat-cli.json").read_text(encoding="utf-8"))
    return golden[case_name]


def _read_golden_stdout(case_name: str) -> str:
    expected = _golden_case(case_name)
    return (GOLDEN_ROOT / expected["output_file"]).read_text(encoding="utf-8")


def _documented_vexy_args(marker: str) -> list[str]:
    command = _extract_marked_bash_command(ROOT / "docs" / "reference" / "cli.md", marker)
    args = shlex.split(command)
    assert args[:4] == ["uv", "run", "--frozen", "vexy"]
    return args[4:]


def _extract_marked_bash_command(path: Path, marker: str) -> str:
    content = path.read_text(encoding="utf-8")
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    marked = content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]
    command_block = marked.split("```bash", maxsplit=1)[1].split("```", maxsplit=1)[0]
    return command_block.strip().replace("\\\n", " ")
