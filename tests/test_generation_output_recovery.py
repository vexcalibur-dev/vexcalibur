from __future__ import annotations

import os
from pathlib import Path

import pytest

import vexcalibur
import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_staging as staging_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
)
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


def _generation_result(monkeypatch: pytest.MonkeyPatch) -> GenerationResult:
    monkeypatch.setattr(vexcalibur, "__version__", "0.4.2")
    monkeypatch.setattr(
        "vexcalibur.generation_result.verify_source_checkout_version",
        lambda version: None,
    )
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2",
    )
    return GenerationResult(
        '{"message":"caf\N{LATIN SMALL LETTER E WITH ACUTE}"}\n',
        (),
        (),
        GenerationExecutionContext(
            InventorySourceCategory.SBOM_FILE,
            FindingSourceCategory.LOCAL_FILE,
            ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )


def _distinct_generation_result(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> GenerationResult:
    result = _generation_result(monkeypatch)
    return GenerationResult(
        f'{{"message":"{message}"}}\n',
        result.components,
        result.findings,
        result.execution_context,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_cleanup_cancellation_removes_the_published_success_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    real_close = destination_module.StagedFileWrite.close
    interrupted = False

    def interrupt_output_cleanup(
        staged: destination_module.StagedFileWrite,
    ) -> None:
        nonlocal interrupted
        if (
            not interrupted
            and staged.destination.requested_path == output_path
            and staged.committed
        ):
            interrupted = True
            raise KeyboardInterrupt("synthetic cleanup cancellation")
        real_close(staged)

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "close",
        interrupt_output_cleanup,
    )

    with (
        transaction,
        pytest.raises(
            KeyboardInterrupt,
            match="synthetic cleanup cancellation",
        ),
    ):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert interrupted
    assert output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_cleanup_retries_a_transient_report_rollback_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    real_close = destination_module.StagedFileWrite.close
    real_remove = staging_module._remove_matching_destination
    cleanup_interrupted = False
    rollback_failed = False

    def interrupt_output_cleanup(
        staged: destination_module.StagedFileWrite,
    ) -> None:
        nonlocal cleanup_interrupted
        if (
            not cleanup_interrupted
            and staged.destination.requested_path == output_path
            and staged.committed
        ):
            cleanup_interrupted = True
            raise KeyboardInterrupt("synthetic cleanup cancellation")
        real_close(staged)

    def fail_first_report_rollback(*args: object, **kwargs: object) -> bool:
        nonlocal rollback_failed
        if not rollback_failed:
            rollback_failed = True
            raise OSError("transient rollback failure")
        return real_remove(*args, **kwargs)

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "close",
        interrupt_output_cleanup,
    )
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        fail_first_report_rollback,
    )

    with (
        transaction,
        pytest.raises(
            KeyboardInterrupt,
            match="synthetic cleanup cancellation",
        ),
    ):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert cleanup_interrupted
    assert rollback_failed
    assert output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_transaction_close_attempts_every_destination_and_can_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=tmp_path / "execution-report.json",
        protected_paths=(),
    )
    output_destination = transaction.output_destination
    report_destination = transaction.report_destination
    assert output_destination is not None
    assert report_destination is not None
    real_close = BoundFileDestination.close
    interrupted = False

    def interrupt_first_output_close(destination: BoundFileDestination) -> None:
        nonlocal interrupted
        if destination is output_destination and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("synthetic destination close cancellation")
        real_close(destination)

    monkeypatch.setattr(
        BoundFileDestination,
        "close",
        interrupt_first_output_close,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic destination close cancellation",
    ):
        transaction.close()

    assert report_destination.closed
    assert not transaction.closed

    transaction.close()

    assert output_destination.closed
    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
@pytest.mark.parametrize("failed_role", ("output", "report"))
def test_destination_close_cancellation_removes_published_success_report(
    failed_role: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(
        _generation_result(monkeypatch),
        binary_stdout=None,
    )
    output_destination = transaction.output_destination
    report_destination = transaction.report_destination
    failed_destination = output_destination if failed_role == "output" else report_destination
    assert failed_destination is not None
    real_close = BoundFileDestination.close
    interrupted = False

    def interrupt_selected_close(destination: BoundFileDestination) -> None:
        nonlocal interrupted
        if destination is failed_destination and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("synthetic destination close cancellation")
        real_close(destination)

    monkeypatch.setattr(
        BoundFileDestination,
        "close",
        interrupt_selected_close,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic destination close cancellation",
    ):
        transaction.close()

    assert output_path.exists()
    assert not report_path.exists()
    transaction.close()
