from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import vexcalibur.generate_command as generate_command
from vexcalibur import cli
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.generation_output import (
    GenerationOutputTransaction,
)
from vexcalibur.generation_result import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)
from vexcalibur.github_sbom import GithubSbomClient
from vexcalibur.sbom import load_cyclonedx_sbom
from vexcalibur.sources.osv import OsvSource

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sbom"
FINDINGS_ROOT = Path(__file__).parent / "fixtures" / "findings"


def test_generate_writes_execution_report_after_vex_output(tmp_path: Path) -> None:
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
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(report_path.read_text(encoding="utf-8"))
    document = output_path.read_bytes()
    assert report["schema_version"] == 1
    assert report["command"] == "generate"
    assert report["inventory_source"] == "sbom_file"
    assert report["finding_source"] == "local_file"
    assert report["output_format"] == "cyclonedx"
    assert report["component_count"] == 2
    assert report["finding_count"] == 5
    assert report["analysis_state_counts"] == {
        "exploitable": 1,
        "false_positive": 1,
        "in_triage": 1,
        "not_affected": 1,
        "resolved": 1,
    }
    assert report["document"] == {
        "sha256": hashlib.sha256(document).hexdigest(),
        "bytes": len(document),
    }


def test_cli_interruption_after_commit_removes_the_success_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_commit = GenerationOutputTransaction.commit

    def commit_then_interrupt(
        transaction: GenerationOutputTransaction,
        result: GenerationResult,
        *,
        binary_stdout: io.BufferedIOBase | None = None,
    ) -> None:
        real_commit(transaction, result, binary_stdout=binary_stdout)
        raise KeyboardInterrupt("post-commit interruption")

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "commit",
        commit_then_interrupt,
    )

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

    assert result.exit_code == 130
    assert isinstance(result.exception, SystemExit)
    assert output_path.exists()
    assert not report_path.exists()


def test_cli_reports_finalization_failure_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"

    def fail_rollback_release(transaction: GenerationOutputTransaction) -> None:
        del transaction
        raise OSError("synthetic release failure")

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "_release_report_rollback",
        fail_rollback_release,
    )

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
    assert "Could not finalize generate outputs: synthetic release failure" in result.output
    assert "Traceback" not in result.output
    assert output_path.exists()
    assert not report_path.exists()


def test_generate_report_counts_repeated_analysis_states(tmp_path: Path) -> None:
    findings_document = json.loads(
        (FINDINGS_ROOT / "all-analysis-states.json").read_text(encoding="utf-8")
    )
    duplicate = dict(findings_document["findings"][3])
    duplicate["id"] = "CVE-2026-0006"
    findings_document["findings"].append(duplicate)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings_document), encoding="utf-8")
    report_path = tmp_path / "execution-report.json"

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(findings_path),
            "--offline",
            "--output",
            str(tmp_path / "vex.json"),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["finding_count"] == 6
    assert report["analysis_state_counts"]["resolved"] == 2


@pytest.mark.parametrize(
    (
        "inventory_arguments",
        "source_arguments",
        "expected_inventory",
        "expected_source",
    ),
    (
        (
            ("local",),
            ("--allow-public-osv",),
            "sbom_file",
            "public_osv",
        ),
        (
            ("local",),
            ("--osv-url", "https://osv.internal.example/private-api"),
            "sbom_file",
            "custom_osv",
        ),
        (
            ("github",),
            ("--allow-public-osv",),
            "github_dependency_graph",
            "public_osv",
        ),
        (
            ("github",),
            ("--osv-url", "https://osv.internal.example/private-api"),
            "github_dependency_graph",
            "custom_osv",
        ),
        (
            ("github",),
            (
                "--findings-file",
                str(FINDINGS_ROOT / "all-analysis-states.json"),
            ),
            "github_dependency_graph",
            "local_file",
        ),
    ),
)
def test_cli_report_records_every_inventory_and_finding_source_category(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    inventory_arguments: tuple[str, ...],
    source_arguments: tuple[str, ...],
    expected_inventory: str,
    expected_source: str,
) -> None:
    input_path = FIXTURE_ROOT / "cyclonedx-json-simple.json"
    private_repository = "private-owner/private-repository"
    components = load_cyclonedx_sbom(input_path)

    def local_osv_result(
        source: OsvSource,
        selected_components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        assert source.effective_base_url
        assert selected_components
        return ()

    def local_github_result(
        client: GithubSbomClient,
        repository: str,
    ) -> tuple[ComponentIdentity, ...]:
        assert client.api_url
        assert repository == private_repository
        return components

    monkeypatch.setattr(OsvSource, "findings_for_components", local_osv_result)
    monkeypatch.setattr(GithubSbomClient, "component_identities", local_github_result)

    report_path = tmp_path / "execution-report.json"
    output_path = tmp_path / "vex.json"
    if inventory_arguments == ("local",):
        selected_inventory_arguments = [str(input_path)]
    else:
        selected_inventory_arguments = ["--github-repo", private_repository]
    result = runner.invoke(
        cli.app,
        [
            "generate",
            *selected_inventory_arguments,
            *source_arguments,
            "--timestamp",
            "2026-06-23T00:00:00Z",
            "--output",
            str(output_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    serialized = report_path.read_text(encoding="utf-8")
    report = json.loads(serialized)
    assert report["inventory_source"] == expected_inventory
    assert report["finding_source"] == expected_source
    for sensitive_value in (
        str(input_path),
        private_repository,
        "https://osv.internal.example/private-api",
    ):
        assert sensitive_value not in serialized


@pytest.mark.parametrize(
    ("output_format", "format_args"),
    (
        ("cyclonedx", ()),
        (
            "openvex",
            (
                "--author",
                "Example Security Team",
                "--author-role",
                "VEX document producer",
            ),
        ),
        (
            "csaf",
            (
                "--csaf-document-id",
                "ACME-VEX-2026-001",
                "--csaf-document-title",
                "ACME component exploitability assessment",
                "--csaf-publisher-name",
                "ACME Product Security",
                "--csaf-publisher-namespace",
                "https://security.example.test",
                "--csaf-publisher-category",
                "vendor",
            ),
        ),
    ),
)
def test_generate_execution_report_matches_stdout_for_each_format(
    tmp_path: Path,
    output_format: str,
    format_args: tuple[str, ...],
) -> None:
    report_path = tmp_path / f"{output_format}-report.json"

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
            "--format",
            output_format,
            *format_args,
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    document = result.output.encode("utf-8")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["output_format"] == output_format
    assert report["component_count"] == 2
    assert report["finding_count"] == 5
    assert report["document"] == {
        "sha256": hashlib.sha256(document).hexdigest(),
        "bytes": len(document),
    }


@pytest.mark.parametrize("write_to_file", (False, True))
def test_execution_report_measures_exact_multibyte_utf8(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    write_to_file: bool,
) -> None:
    document_text = '{"summary":"caf\N{LATIN SMALL LETTER E WITH ACUTE}"}\n'
    document = document_text.encode("utf-8")
    monkeypatch.setattr(
        generate_command,
        "generate_vex_from_sbom_result",
        lambda **kwargs: GenerationResult(
            document_text,
            (),
            (),
            GenerationExecutionContext(
                InventorySourceCategory.SBOM_FILE,
                FindingSourceCategory.CUSTOM_OSV,
                ExecutionReportOutputFormat.CYCLONEDX,
            ),
        ),
    )
    report_path = tmp_path / "execution-report.json"
    output_path = tmp_path / "vex.json"
    arguments = [
        "generate",
        str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
        "--osv-url",
        "https://osv.internal.example",
        "--execution-report",
        str(report_path),
    ]
    if write_to_file:
        arguments.extend(("--output", str(output_path)))

    result = runner.invoke(cli.app, arguments)

    assert result.exit_code == 0, result.output
    emitted = output_path.read_bytes() if write_to_file else result.output.encode("utf-8")
    assert emitted == document
    assert json.loads(report_path.read_text(encoding="utf-8"))["document"] == {
        "sha256": hashlib.sha256(document).hexdigest(),
        "bytes": len(document),
    }


def test_failed_generation_removes_stale_execution_report(tmp_path: Path) -> None:
    sbom_path = tmp_path / "invalid.json"
    sbom_path.write_text("{not json", encoding="utf-8")
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(sbom_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert not report_path.exists()
    assert "Traceback" not in result.output


def test_invalid_timestamp_removes_stale_execution_report(tmp_path: Path) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--timestamp",
            "not-a-timestamp",
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code != 0
    assert not report_path.exists()
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "arguments",
    (
        ("--format", "invalid"),
        ("--unknown-option", "value"),
    ),
)
def test_parser_failure_preserves_unverified_stale_execution_report(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            *arguments,
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code != 0
    assert report_path.read_text(encoding="utf-8") == '{"stale":true}\n'


def test_missing_input_preserves_unverified_stale_execution_report(tmp_path: Path) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(tmp_path / "missing-sbom.json"),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code != 0
    assert report_path.read_text(encoding="utf-8") == '{"stale":true}\n'


def test_missing_findings_file_preserves_unverified_stale_execution_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--findings-file",
            str(tmp_path / "missing-findings.json"),
            "--offline",
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code != 0
    assert report_path.read_text(encoding="utf-8") == '{"stale":true}\n'


def test_generate_help_preserves_existing_report(tmp_path: Path) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--execution-report",
            str(report_path),
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert report_path.read_text(encoding="utf-8") == '{"stale":true}\n'
