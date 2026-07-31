from __future__ import annotations

import os
from pathlib import Path

import pytest

import vexcalibur
import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_filesystem as filesystem_module
import vexcalibur.execution_report_staging as staging_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
)
from vexcalibur.generation_output import (
    GenerationOutputError,
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
def test_rollback_handoff_cancellation_removes_the_published_success_report(
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
    real_setattr = GenerationOutputTransaction.__setattr__
    interrupted = False

    def interrupt_rollback_handoff(
        target: GenerationOutputTransaction,
        name: str,
        value: object,
    ) -> None:
        nonlocal interrupted
        if not interrupted and name == "_report_rollback" and value is not None:
            interrupted = True
            raise KeyboardInterrupt("synthetic rollback handoff cancellation")
        real_setattr(target, name, value)

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "__setattr__",
        interrupt_rollback_handoff,
    )

    with (
        transaction,
        pytest.raises(
            KeyboardInterrupt,
            match="synthetic rollback handoff cancellation",
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
def test_exception_after_commit_removes_the_published_success_report(
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

    with pytest.raises(KeyboardInterrupt, match="post-commit interruption"), transaction:
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )
        raise KeyboardInterrupt("post-commit interruption")

    assert output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_rollback_release_cancellation_removes_the_published_success_report(
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
    real_close = staging_module.PublishedFileRollback.close
    interrupted = False

    def interrupt_rollback_release(
        rollback: staging_module.PublishedFileRollback,
    ) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("synthetic rollback release cancellation")
        real_close(rollback)

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "close",
        interrupt_rollback_release,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic rollback release cancellation",
    ):
        transaction.close()

    assert interrupted
    assert output_path.exists()
    assert not report_path.exists()
    transaction.close()

    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_interrupted_rollback_descriptor_release_removes_success_report(
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
    rollback = transaction._report_rollback
    assert rollback is not None
    published_descriptor = rollback.published_fd
    real_dup2 = filesystem_module.os.dup2
    interrupted = False

    def interrupt_published_transfer(
        source: int,
        candidate: int,
        *,
        inheritable: bool = True,
    ) -> int:
        nonlocal interrupted
        if candidate == published_descriptor and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("published descriptor close interrupted")
        return real_dup2(source, candidate, inheritable=inheritable)

    monkeypatch.setattr(
        filesystem_module.os,
        "dup2",
        interrupt_published_transfer,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="published descriptor close interrupted",
    ):
        transaction.close()

    assert interrupted
    assert output_path.exists()
    assert not report_path.exists()
    assert transaction._report_rollback is None
    os.close(published_descriptor)
    transaction.close()

    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_interruption_after_physical_rollback_release_keeps_success_report(
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
    real_close = staging_module.PublishedFileRollback.close

    def close_then_interrupt(
        rollback: staging_module.PublishedFileRollback,
    ) -> None:
        if rollback.closed:
            return
        real_close(rollback)
        raise KeyboardInterrupt("rollback was already released")

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "close",
        close_then_interrupt,
    )

    transaction.close()

    assert transaction.closed
    assert transaction._report_rollback is None
    assert output_path.exists()
    assert report_path.exists()


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


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_persistent_report_rollback_failure_remains_retryable(
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
    assert output_destination is not None
    real_close = BoundFileDestination.close
    real_remove = staging_module._remove_matching_destination
    interrupted = False

    def interrupt_output_close(destination: BoundFileDestination) -> None:
        nonlocal interrupted
        if destination is output_destination and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("synthetic destination close cancellation")
        real_close(destination)

    monkeypatch.setattr(BoundFileDestination, "close", interrupt_output_close)
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        lambda **kwargs: False,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic destination close cancellation",
    ):
        transaction.close()

    assert report_path.exists()
    assert transaction._report_rollback is not None
    assert transaction._discard_report_on_close
    assert not transaction.closed

    with pytest.raises(
        GenerationOutputError,
        match="could not remove the published execution report",
    ):
        transaction.close()

    assert report_path.exists()
    assert transaction._report_rollback is not None
    assert transaction._discard_report_on_close
    assert not transaction.closed

    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        real_remove,
    )
    transaction.close()

    assert output_path.exists()
    assert not report_path.exists()
    assert transaction._report_rollback is None
    assert not transaction._discard_report_on_close
    assert transaction.closed
