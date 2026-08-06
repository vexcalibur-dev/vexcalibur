from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import sys
from pathlib import Path

import pytest
from typer.core import TyperGroup
from typer.main import get_command
from typer.testing import CliRunner

import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_staging as staging_module
import vexcalibur.generate_command as generate_command
from vexcalibur import cli
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.execution_report_destination import BoundFileDestinationError
from vexcalibur.generation_output import GenerationOutputTransaction
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


def test_cli_interruption_preserves_a_newer_report_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    replacement_path = tmp_path / "replacement.json"
    replacement = b'{"writer":"newer"}\n'
    real_commit = GenerationOutputTransaction.commit

    def commit_replace_then_interrupt(
        transaction: GenerationOutputTransaction,
        result: GenerationResult,
        *,
        binary_stdout: io.BufferedIOBase | None = None,
    ) -> None:
        real_commit(transaction, result, binary_stdout=binary_stdout)
        replacement_path.write_bytes(replacement)
        replacement_path.chmod(0o600)
        replacement_path.replace(report_path)
        raise KeyboardInterrupt("post-commit interruption")

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "commit",
        commit_replace_then_interrupt,
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
    assert output_path.exists()
    assert report_path.read_bytes() == replacement


def test_cli_interruption_after_rollback_release_exits_successfully(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_release = GenerationOutputTransaction._release_report_rollback

    def release_then_interrupt(transaction: GenerationOutputTransaction) -> bool:
        released = real_release(transaction)
        assert released
        raise KeyboardInterrupt("post-release interruption")

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "_release_report_rollback",
        release_then_interrupt,
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

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert report_path.exists()


def test_cli_interruption_after_transaction_close_exits_successfully(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_close = GenerationOutputTransaction.close
    interrupted = False

    def close_then_interrupt(transaction: GenerationOutputTransaction) -> None:
        nonlocal interrupted
        if transaction.closed:
            return
        real_close(transaction)
        assert transaction.closed
        interrupted = True
        raise KeyboardInterrupt("post-close interruption")

    monkeypatch.setattr(GenerationOutputTransaction, "close", close_then_interrupt)

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

    assert interrupted
    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX process signal contract")
def test_cli_interruption_before_irreversible_marker_exits_successfully(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_record = cli._record_irreversible_publication
    interrupted = False

    def interrupt_then_record(
        transaction: GenerationOutputTransaction | None,
    ) -> None:
        nonlocal interrupted
        interrupted = True
        os.kill(os.getpid(), signal.SIGINT)
        real_record(transaction)

    monkeypatch.setattr(cli, "_record_irreversible_publication", interrupt_then_record)

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

    assert interrupted
    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert report_path.exists()


def test_group_does_not_reuse_irreversible_publication_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = get_command(cli.app)
    assert isinstance(command, cli._VexcaliburGroup)
    calls = 0

    def interrupt_after_optional_publication(
        group: TyperGroup,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal calls
        del group, args, kwargs
        calls += 1
        if calls == 3:
            raise KeyboardInterrupt("unpublished interruption")
        if calls == 1:
            cli._generate_irreversible_publication.set(True)
        raise SystemExit(130)

    monkeypatch.setattr(TyperGroup, "main", interrupt_after_optional_publication)

    assert command.main(args=("generate",)) is None
    with pytest.raises(SystemExit, match="130"):
        command.main(args=("query-osv",))
    with pytest.raises(KeyboardInterrupt, match="unpublished interruption"):
        command.main(args=("query-osv",))


@pytest.mark.skipif(os.name == "nt", reason="POSIX process signal contract")
def test_cli_sigint_during_framework_success_exit_remains_successful(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_exit = sys.exit
    interrupted = False

    def interrupt_success_exit(code: object = None) -> None:
        nonlocal interrupted
        if code in {None, 0} and not interrupted:
            interrupted = True
            os.kill(os.getpid(), signal.SIGINT)
        real_exit(code)

    monkeypatch.setattr(sys, "exit", interrupt_success_exit)

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

    assert interrupted
    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert report_path.exists()


def test_cli_reports_persistent_abort_failure(
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

    def fail_discard(rollback: staging_module.PublishedFileRollback) -> bool:
        del rollback
        raise OSError("synthetic persistent abort failure")

    monkeypatch.setattr(GenerationOutputTransaction, "commit", commit_then_interrupt)
    monkeypatch.setattr(staging_module.PublishedFileRollback, "discard", fail_discard)

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
    expected_error = (
        "Could not finalize generate outputs: could not remove the published execution report"
    )
    assert expected_error in result.output
    assert "Traceback" not in result.output
    assert output_path.exists()
    assert report_path.exists()


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


def test_cli_normalizes_staged_cleanup_failure_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    real_close = destination_module.StagedFileWrite.close
    failed = False

    def close_then_fail(staged: destination_module.StagedFileWrite) -> None:
        nonlocal failed
        was_committed = staged.committed
        real_close(staged)
        if staged.destination.requested_path == output_path and was_committed and not failed:
            failed = True
            raise BoundFileDestinationError("synthetic staged cleanup failure")

    monkeypatch.setattr(destination_module.StagedFileWrite, "close", close_then_fail)

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

    assert failed
    assert result.exit_code == 1
    assert "Could not finalize generate outputs: synthetic staged cleanup failure" in result.output
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
def test_parser_failure_removes_stale_execution_report(
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
    assert not report_path.exists()


def test_parser_cleanup_uses_arguments_received_by_typer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw_report = "%VEXCALIBUR_REPORT%"
    expanded_report = str(tmp_path / "expanded-report.json")
    raw_arguments = ("generate", "--execution-report", raw_report, "--unknown-option")
    expanded_arguments = (
        "generate",
        "--execution-report",
        expanded_report,
        "--unknown-option",
    )
    observed: list[tuple[str, ...]] = []
    command = get_command(cli.app)
    assert isinstance(command, cli._VexcaliburGroup)

    def expand_then_fail(
        group: TyperGroup,
        args: object = None,
        **kwargs: object,
    ) -> object:
        del args, kwargs
        group.make_context("vexcalibur", list(expanded_arguments))
        raise SystemExit(2)

    def observe_cleanup(
        group: cli._VexcaliburGroup,
        arguments: tuple[str, ...],
    ) -> BaseException | None:
        assert group is command
        observed.append(arguments)
        return None

    monkeypatch.setattr(TyperGroup, "main", expand_then_fail)
    monkeypatch.setattr(cli, "_remove_failed_generate_report", observe_cleanup)

    with pytest.raises(SystemExit, match="2"):
        command.main(args=raw_arguments)

    assert observed == [expanded_arguments]


def test_option_scanning_stops_at_the_positional_terminator(tmp_path: Path) -> None:
    sentinel_path = tmp_path / "sentinel.json"
    sentinel_path.write_text('{"keep":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--",
            "--execution-report",
            str(sentinel_path),
        ],
    )

    assert result.exit_code != 0
    assert sentinel_path.read_text(encoding="utf-8") == '{"keep":true}\n'


def test_group_positional_terminator_still_removes_stale_report(tmp_path: Path) -> None:
    report_path = tmp_path / "execution-report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "--",
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--format",
            "invalid",
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code != 0
    assert not report_path.exists()


def test_known_non_path_option_does_not_protect_stale_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text('{"stale":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--format",
            str(report_path),
            "--execution-report",
            str(report_path),
        ],
    )

    assert result.exit_code != 0
    assert not report_path.exists()


def test_leading_hyphen_input_remains_protected_after_parser_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_path = Path("-input")
    input_path.write_text('{"sentinel":true}\n', encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "generate",
            "--execution-report=-input",
            "--",
            "-input",
            "extra",
        ],
    )

    assert result.exit_code != 0
    assert input_path.read_text(encoding="utf-8") == '{"sentinel":true}\n'


def test_parser_cleanup_failure_emits_sanitized_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_failure = KeyboardInterrupt("sensitive path detail")

    def fail_cleanup_prepare(
        cls: type[GenerationOutputTransaction],
        **kwargs: object,
    ) -> GenerationOutputTransaction:
        raise cleanup_failure

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "prepare",
        classmethod(fail_cleanup_prepare),
    )

    result = runner.invoke(
        cli.app,
        [
            "generate",
            str(FIXTURE_ROOT / "cyclonedx-json-simple.json"),
            "--format",
            "invalid",
            "--execution-report",
            str(tmp_path / "execution-report.json"),
        ],
    )

    assert result.exit_code != 0
    assert "Could not remove the stale execution report" in result.output
    assert "sensitive path detail" not in result.output
    assert result.exception is not None
    assert result.exception.vexcalibur_cleanup_failures == (cleanup_failure,)  # type: ignore[attr-defined]


def test_missing_input_removes_stale_execution_report(tmp_path: Path) -> None:
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
    assert not report_path.exists()


def test_missing_findings_file_removes_stale_execution_report(
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
    assert not report_path.exists()


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
