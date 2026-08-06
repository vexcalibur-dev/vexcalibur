from __future__ import annotations

import errno
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
from vexcalibur.execution_report_lifecycle import (
    DescriptorOwnership,
    GenerationOutputState,
    PublishedRollbackState,
)
from vexcalibur.generation_output import (
    GenerationDocumentWriteError,
    GenerationOutputCleanupError,
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
def test_descriptor_exhaustion_after_publication_uses_retained_rollback_lock(
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
    real_pipe = filesystem_module.os.pipe

    def exhaust_after_publication() -> tuple[int, int]:
        if report_path.exists():
            raise OSError(errno.EMFILE, "synthetic descriptor exhaustion")
        return real_pipe()

    monkeypatch.setattr(filesystem_module.os, "pipe", exhaust_after_publication)
    with pytest.raises(GenerationOutputCleanupError, match="descriptor exhaustion"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert output_path.exists()
    assert not report_path.exists()

    monkeypatch.setattr(filesystem_module.os, "pipe", real_pipe)
    transaction.abort()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_transaction_owns_rollback_guard_before_descriptor_acquisition(
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
    rollback = transaction._report_rollback
    interrupted = False

    def interrupt_before_descriptor_acquisition(
        staged: staging_module.StagedFileWrite,
        supplied_rollback: staging_module.PublishedFileRollback | None = None,
    ) -> staging_module.PublishedFileRollback:
        nonlocal interrupted
        del staged
        assert supplied_rollback is rollback
        assert transaction.state is GenerationOutputState.REPORT_GUARD_ARMING
        interrupted = True
        raise KeyboardInterrupt("synthetic rollback acquisition cancellation")

    monkeypatch.setattr(
        staging_module.StagedFileWrite,
        "_prepare_rollback",
        interrupt_before_descriptor_acquisition,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic rollback acquisition cancellation",
    ):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert interrupted
    assert rollback.closed
    assert transaction.closed
    assert output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_transaction_retains_preowned_guard_when_rollback_dup_is_interrupted(
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
    rollback = transaction._report_rollback
    real_arm = staging_module.PublishedFileRollback._arm
    real_dup = staging_module.os.dup
    duplicate_calls = 0

    def interrupt_second_duplicate(descriptor: int) -> int:
        nonlocal duplicate_calls
        duplicate_calls += 1
        if duplicate_calls == 2:
            raise KeyboardInterrupt("rollback acquisition interrupted")
        return real_dup(descriptor)

    def arm_with_interrupted_duplicate(
        selected: staging_module.PublishedFileRollback,
        *,
        expected: os.stat_result,
        parent_fd: int,
        published_fd: int,
        name: str | bytes,
    ) -> None:
        monkeypatch.setattr(staging_module.os, "dup", interrupt_second_duplicate)
        try:
            real_arm(
                selected,
                expected=expected,
                parent_fd=parent_fd,
                published_fd=published_fd,
                name=name,
            )
        finally:
            monkeypatch.setattr(staging_module.os, "dup", real_dup)

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "_arm",
        arm_with_interrupted_duplicate,
    )

    with pytest.raises(KeyboardInterrupt, match="rollback acquisition interrupted"):
        transaction.commit(_generation_result(monkeypatch), binary_stdout=None)

    assert transaction._report_rollback is rollback
    assert duplicate_calls == 2
    assert output_path.exists()
    assert not report_path.exists()
    assert rollback.state is PublishedRollbackState.RELEASED
    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_ambiguous_destination_release_never_closes_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    destination = transaction.report_destination
    descriptor = destination._parent_descriptor
    real_release = staging_module._close_descriptor_retryable
    interrupted = False

    def interrupt_destination_release(candidate: int) -> object:
        nonlocal interrupted
        if candidate == descriptor and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("destination release interrupted")
        return real_release(candidate)

    monkeypatch.setattr(
        staging_module,
        "_close_descriptor_retryable",
        interrupt_destination_release,
    )
    try:
        with pytest.raises(KeyboardInterrupt, match="destination release interrupted"):
            transaction.close()

        assert interrupted
        assert not report_path.exists()
        assert not destination.closed
        assert destination._parent_descriptor_ownership is DescriptorOwnership.AMBIGUOUS
        assert transaction.state is GenerationOutputState.ABORT_REQUIRED
        assert not transaction.closed
        os.fstat(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_rollback_acquisition_cleanup_failure_retains_transaction_ownership(
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
    real_close = staging_module.PublishedFileRollback.close
    rollback = transaction._report_rollback

    def interrupt_before_descriptor_acquisition(
        staged: staging_module.StagedFileWrite,
        supplied_rollback: staging_module.PublishedFileRollback | None = None,
    ) -> staging_module.PublishedFileRollback:
        del staged
        assert supplied_rollback is rollback
        raise KeyboardInterrupt("synthetic rollback acquisition cancellation")

    def fail_rollback_close(rollback: staging_module.PublishedFileRollback) -> None:
        raise OSError("synthetic rollback close failure")

    monkeypatch.setattr(
        staging_module.StagedFileWrite,
        "_prepare_rollback",
        interrupt_before_descriptor_acquisition,
    )
    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "close",
        fail_rollback_close,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic rollback acquisition cancellation",
    ) as captured:
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert transaction._report_rollback is rollback
    assert transaction.state is GenerationOutputState.ABORT_REQUIRED
    assert not rollback.closed
    assert str(captured.value.vexcalibur_cleanup_failures[0]) == (  # type: ignore[attr-defined]
        "synthetic rollback close failure"
    )
    assert output_path.exists()
    assert not report_path.exists()

    monkeypatch.setattr(staging_module.PublishedFileRollback, "close", real_close)
    transaction.abort()

    assert rollback.closed
    assert transaction.closed


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
@pytest.mark.parametrize("descriptor_role", ("published_fd", "parent_fd", "lock_fd"))
def test_interrupted_rollback_descriptor_release_becomes_ambiguous(
    descriptor_role: str,
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
    interrupted_descriptor = getattr(rollback, descriptor_role)
    real_dup2 = filesystem_module.os.dup2
    interrupted = False

    def interrupt_published_transfer(
        source: int,
        candidate: int,
        *,
        inheritable: bool = True,
    ) -> int:
        nonlocal interrupted
        if candidate == interrupted_descriptor and not interrupted:
            interrupted = True
            raise KeyboardInterrupt(f"{descriptor_role} close interrupted")
        return real_dup2(source, candidate, inheritable=inheritable)

    monkeypatch.setattr(
        filesystem_module.os,
        "dup2",
        interrupt_published_transfer,
    )

    transaction.close()

    assert interrupted
    assert output_path.exists()
    assert report_path.exists()
    ownership = getattr(rollback, f"_{descriptor_role}_ownership")
    assert ownership is DescriptorOwnership.AMBIGUOUS
    assert getattr(rollback, descriptor_role) == -1
    for other_role in {"published_fd", "parent_fd", "lock_fd"} - {descriptor_role}:
        assert getattr(rollback, f"_{other_role}_ownership") is DescriptorOwnership.RELEASED
    assert transaction._report_rollback is rollback
    assert transaction.state is GenerationOutputState.FINALIZING
    assert not transaction.closed
    os.fstat(interrupted_descriptor)
    transaction.close()
    assert transaction.state is GenerationOutputState.FINALIZING
    os.close(interrupted_descriptor)


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
    assert transaction._report_rollback.closed
    assert output_path.exists()
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_interruption_after_rollback_release_returns_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    real_release = GenerationOutputTransaction._release_report_rollback

    def release_then_interrupt(candidate: GenerationOutputTransaction) -> bool:
        released = real_release(candidate)
        assert candidate._report_rollback.state is PublishedRollbackState.PUBLICATION_RELEASED
        assert released
        raise KeyboardInterrupt("post-release interruption")

    monkeypatch.setattr(
        GenerationOutputTransaction,
        "_release_report_rollback",
        release_then_interrupt,
    )

    transaction.close()

    assert transaction.closed
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_release_probe_failure_retains_interrupt_as_primary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    rollback = transaction._report_rollback
    real_close = staging_module.PublishedFileRollback.close
    real_fstat = staging_module.os.fstat

    def interrupt_release(candidate: staging_module.PublishedFileRollback) -> None:
        del candidate
        raise KeyboardInterrupt("synthetic rollback release cancellation")

    def fail_probe(descriptor: int) -> os.stat_result:
        if descriptor == rollback.published_fd:
            raise OSError(errno.EIO, "synthetic rollback probe failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(staging_module.PublishedFileRollback, "close", interrupt_release)
    monkeypatch.setattr(staging_module.os, "fstat", fail_probe)

    with pytest.raises(KeyboardInterrupt, match="release cancellation") as captured:
        transaction.close()

    cleanup_failures = captured.value.vexcalibur_cleanup_failures  # type: ignore[attr-defined]
    assert any("could not inspect" in str(failure) for failure in cleanup_failures)
    assert transaction.state is GenerationOutputState.ABORT_REQUIRED
    assert report_path.exists()

    monkeypatch.setattr(staging_module.PublishedFileRollback, "close", real_close)
    monkeypatch.setattr(staging_module.os, "fstat", real_fstat)
    transaction.abort()

    assert transaction.closed
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_abort_after_rollback_point_of_no_return_finishes_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    rollback = transaction._report_rollback
    real_close = staging_module.PublishedFileRollback.close
    interrupted = False

    def release_publication_then_interrupt(
        candidate: staging_module.PublishedFileRollback,
    ) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            staging_module._close_owned_descriptor(candidate, "published_fd")
            raise KeyboardInterrupt("publication descriptor released")
        real_close(candidate)

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "close",
        release_publication_then_interrupt,
    )

    transaction.close()

    assert transaction.state is GenerationOutputState.FINALIZING
    assert rollback._published_fd_ownership is DescriptorOwnership.RELEASED
    assert rollback._parent_fd_ownership is DescriptorOwnership.OWNED
    assert rollback._lock_fd_ownership is DescriptorOwnership.OWNED

    monkeypatch.setattr(staging_module.PublishedFileRollback, "close", real_close)
    transaction.abort()

    assert transaction.closed
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_persistent_release_failure_after_point_of_no_return_stays_finalizing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    rollback = transaction._report_rollback
    parent_descriptor = rollback.parent_fd
    real_release = staging_module._close_descriptor_retryable

    def fail_parent_release(descriptor: int) -> object:
        if descriptor == parent_descriptor:
            return filesystem_module._DescriptorCloseOutcome(
                released=False,
                unchanged=True,
                failure=OSError(errno.EMFILE, "synthetic descriptor exhaustion"),
            )
        return real_release(descriptor)

    monkeypatch.setattr(
        staging_module,
        "_close_descriptor_retryable",
        fail_parent_release,
    )

    transaction.close()

    assert report_path.exists()
    assert transaction.state is GenerationOutputState.FINALIZING
    assert not transaction.closed
    assert rollback._published_fd_ownership is DescriptorOwnership.RELEASED
    assert rollback._parent_fd_ownership is DescriptorOwnership.OWNED

    monkeypatch.setattr(
        staging_module,
        "_close_descriptor_retryable",
        real_release,
    )
    transaction.close()

    assert transaction.closed
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_rollback_release_stops_while_complete_authority_remains(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    rollback = transaction._report_rollback
    published_descriptor = rollback.published_fd
    real_release = staging_module._close_descriptor_retryable

    def fail_published_release(descriptor: int) -> object:
        if descriptor == published_descriptor:
            return filesystem_module._DescriptorCloseOutcome(
                released=False,
                unchanged=True,
                failure=OSError(errno.EMFILE, "synthetic descriptor exhaustion"),
            )
        return real_release(descriptor)

    monkeypatch.setattr(
        staging_module,
        "_close_descriptor_retryable",
        fail_published_release,
    )

    with pytest.raises(OSError, match="synthetic descriptor exhaustion"):
        rollback.close()

    assert rollback._published_fd_ownership is DescriptorOwnership.OWNED
    assert rollback._parent_fd_ownership is DescriptorOwnership.OWNED
    assert rollback._lock_fd_ownership is DescriptorOwnership.OWNED
    assert rollback.can_discard

    monkeypatch.setattr(
        staging_module,
        "_close_descriptor_retryable",
        real_release,
    )
    transaction.abort()

    assert transaction.closed
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
    real_discard = staging_module.PublishedFileRollback.discard
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

    def fail_first_report_rollback(
        rollback: staging_module.PublishedFileRollback,
    ) -> bool:
        nonlocal rollback_failed
        if not rollback_failed:
            rollback_failed = True
            raise OSError("transient rollback failure")
        return real_discard(rollback)

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "close",
        interrupt_output_cleanup,
    )
    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "discard",
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
def test_abort_preserves_rollback_ownership_after_a_transient_probe_failure(
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
    real_fstat = staging_module.os.fstat
    failed = False

    def fail_rollback_probe(descriptor: int) -> os.stat_result:
        nonlocal failed
        if descriptor == rollback.published_fd and not failed:
            failed = True
            raise OSError(errno.EIO, "synthetic rollback probe failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(staging_module.os, "fstat", fail_rollback_probe)

    with pytest.raises(
        GenerationOutputCleanupError,
        match="could not inspect the published execution report",
    ):
        transaction.abort()

    assert failed
    assert report_path.exists()
    assert transaction._report_rollback is rollback
    assert transaction.state is GenerationOutputState.ABORT_REQUIRED
    assert rollback.state is PublishedRollbackState.PUBLISHED
    assert not transaction.closed

    monkeypatch.setattr(staging_module.os, "fstat", real_fstat)
    transaction.abort()

    assert not report_path.exists()
    assert rollback.state is PublishedRollbackState.DISCARDED_RELEASED
    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
@pytest.mark.parametrize("failed_attribute", ("published_fd", "parent_fd", "lock_fd"))
def test_transient_rollback_release_failure_preserves_success_marker(
    failed_attribute: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=report_path,
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    rollback = transaction._report_rollback
    failed_descriptor = getattr(rollback, failed_attribute)
    real_release = staging_module._close_descriptor_retryable
    failed = False

    def fail_once(descriptor: int) -> object:
        nonlocal failed
        if descriptor == failed_descriptor and not failed:
            failed = True
            return filesystem_module._DescriptorCloseOutcome(
                released=False,
                unchanged=True,
                failure=OSError(errno.EMFILE, "synthetic descriptor exhaustion"),
            )
        return real_release(descriptor)

    monkeypatch.setattr(staging_module, "_close_descriptor_retryable", fail_once)

    transaction.close()

    assert failed
    assert transaction.closed
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_output_path_rebinding_after_report_publication_removes_success_marker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_parent = tmp_path / "output"
    report_parent = tmp_path / "report"
    moved_output_parent = tmp_path / "moved-output"
    output_parent.mkdir()
    report_parent.mkdir()
    output_path = output_parent / "result.json"
    report_path = report_parent / "result.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    report_destination = transaction.report_destination
    real_commit = staging_module.StagedFileWrite.commit
    rebound = False

    def commit_then_rebind(
        staged: staging_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        nonlocal rebound
        real_commit(staged, destination_lock_held=destination_lock_held)
        if staged.destination is report_destination:
            output_parent.rename(moved_output_parent)
            output_parent.symlink_to(report_parent, target_is_directory=True)
            rebound = True

    monkeypatch.setattr(staging_module.StagedFileWrite, "commit", commit_then_rebind)

    with pytest.raises(GenerationDocumentWriteError, match="parent directory changed"):
        transaction.commit(_generation_result(monkeypatch), binary_stdout=None)

    assert rebound
    assert not report_path.exists()
    assert not output_path.exists()
    assert (moved_output_parent / "result.json").exists()
    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_output_inode_replacement_after_report_publication_removes_success_marker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    replacement_path = tmp_path / "replacement.json"
    report_path = tmp_path / "execution-report.json"
    replacement_path.write_text('{"replacement":true}\n', encoding="utf-8")
    replacement_path.chmod(0o600)
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    report_destination = transaction.report_destination
    real_commit = staging_module.StagedFileWrite.commit

    def commit_then_replace_output(
        staged: staging_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        real_commit(staged, destination_lock_held=destination_lock_held)
        if staged.destination is report_destination:
            output_path.unlink()
            replacement_path.rename(output_path)

    monkeypatch.setattr(
        staging_module.StagedFileWrite,
        "commit",
        commit_then_replace_output,
    )

    with pytest.raises(GenerationDocumentWriteError, match="published file changed"):
        transaction.commit(_generation_result(monkeypatch), binary_stdout=None)

    assert output_path.read_text(encoding="utf-8") == '{"replacement":true}\n'
    assert not report_path.exists()
    assert transaction.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_context_exit_retains_persistent_abort_failure_on_primary_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transaction = GenerationOutputTransaction.prepare(
        output_path=tmp_path / "vex.json",
        report_path=tmp_path / "execution-report.json",
        protected_paths=(),
    )
    transaction.commit(_generation_result(monkeypatch), binary_stdout=None)
    real_discard = staging_module.PublishedFileRollback.discard

    def fail_discard(rollback: staging_module.PublishedFileRollback) -> bool:
        del rollback
        raise OSError("synthetic persistent abort failure")

    monkeypatch.setattr(staging_module.PublishedFileRollback, "discard", fail_discard)

    with (
        pytest.raises(RuntimeError, match="synthetic primary failure") as captured,
        transaction,
    ):
        raise RuntimeError("synthetic primary failure")

    cleanup_failures = captured.value.vexcalibur_cleanup_failures  # type: ignore[attr-defined]
    assert len(cleanup_failures) == 1
    assert str(cleanup_failures[0]) == "could not remove the published execution report"
    assert transaction.state is GenerationOutputState.ABORT_REQUIRED
    assert not transaction.closed

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "discard",
        real_discard,
    )
    transaction.abort()
    assert transaction.closed


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
    real_discard = staging_module.PublishedFileRollback.discard
    interrupted = False

    def interrupt_output_close(destination: BoundFileDestination) -> None:
        nonlocal interrupted
        if destination is output_destination and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("synthetic destination close cancellation")
        real_close(destination)

    monkeypatch.setattr(BoundFileDestination, "close", interrupt_output_close)
    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "discard",
        lambda rollback: False,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="synthetic destination close cancellation",
    ):
        transaction.close()

    assert report_path.exists()
    assert transaction.state is GenerationOutputState.ABORT_REQUIRED
    assert transaction._report_rollback.state is PublishedRollbackState.PUBLISHED
    assert not transaction.closed

    with pytest.raises(
        GenerationOutputError,
        match="could not remove the published execution report",
    ):
        transaction.close()

    assert report_path.exists()
    assert transaction.state is GenerationOutputState.ABORT_REQUIRED
    assert transaction._report_rollback.state is PublishedRollbackState.PUBLISHED
    assert not transaction.closed

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "discard",
        real_discard,
    )
    transaction.close()

    assert output_path.exists()
    assert not report_path.exists()
    assert transaction._report_rollback.state is PublishedRollbackState.DISCARDED_RELEASED
    assert transaction.closed
