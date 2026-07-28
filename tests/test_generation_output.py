from __future__ import annotations

import errno
import io
import os
import threading
from contextlib import AbstractContextManager
from pathlib import Path

import pytest

import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_locks as lock_module
import vexcalibur.execution_report_staging as staging_module
import vexcalibur.generation_output as generation_output_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
    BoundFileDestinationError,
)
from vexcalibur.generation_output import (
    GenerationDocumentWriteError,
    GenerationOutputError,
    GenerationOutputPreparationError,
    GenerationOutputTransaction,
    GenerationReportWriteError,
)
from vexcalibur.generation_result import (
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)


def _generation_result(monkeypatch: pytest.MonkeyPatch) -> GenerationResult:
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
def test_prepare_cancellation_closes_every_bound_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[BoundFileDestination] = []
    real_prepare = BoundFileDestination.prepare.__func__
    real_aliases = BoundFileDestination.aliases

    def observe_prepare(
        cls: type[BoundFileDestination],
        path: Path,
        **kwargs: object,
    ) -> BoundFileDestination:
        destination = real_prepare(cls, path, **kwargs)
        observed.append(destination)
        return destination

    def cancel_final_alias_check(
        destination: BoundFileDestination,
        other: Path | BoundFileDestination,
    ) -> bool:
        if isinstance(other, BoundFileDestination):
            raise KeyboardInterrupt
        return real_aliases(destination, other)

    monkeypatch.setattr(
        BoundFileDestination,
        "prepare",
        classmethod(observe_prepare),
    )
    monkeypatch.setattr(
        BoundFileDestination,
        "aliases",
        cancel_final_alias_check,
    )

    with pytest.raises(KeyboardInterrupt):
        GenerationOutputTransaction.prepare(
            output_path=tmp_path / "vex.json",
            report_path=tmp_path / "execution-report.json",
            protected_paths=(),
        )

    assert len(observed) == 2
    for destination in observed:
        with pytest.raises(OSError):
            os.fstat(destination._parent_descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_prepare_retargeted_output_parent_closes_every_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_parent = tmp_path / "report-parent"
    output_parent = tmp_path / "output-parent"
    moved_output_parent = tmp_path / "moved-output-parent"
    report_parent.mkdir()
    output_parent.mkdir()
    observed: list[BoundFileDestination] = []
    real_prepare = BoundFileDestination.prepare.__func__

    def retarget_after_report(
        cls: type[BoundFileDestination],
        path: Path,
        **kwargs: object,
    ) -> BoundFileDestination:
        destination = real_prepare(cls, path, **kwargs)
        observed.append(destination)
        if len(observed) == 1:
            output_parent.rename(moved_output_parent)
            output_parent.symlink_to(report_parent, target_is_directory=True)
        return destination

    monkeypatch.setattr(
        BoundFileDestination,
        "prepare",
        classmethod(retarget_after_report),
    )

    with pytest.raises(GenerationOutputPreparationError, match="must not replace") as captured:
        GenerationOutputTransaction.prepare(
            output_path=output_parent / "result.json",
            report_path=report_parent / "result.json",
            protected_paths=(),
        )

    assert isinstance(captured.value, GenerationOutputError)
    assert captured.value.role == "execution report"
    assert captured.value.destination == report_parent / "result.json"
    assert len(observed) == 2
    for destination in observed:
        with pytest.raises(OSError):
            os.fstat(destination._parent_descriptor)
    assert not (report_parent / "result.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
@pytest.mark.parametrize(
    ("failed_role", "expected_error"),
    (
        ("report", GenerationReportWriteError),
        ("output", GenerationDocumentWriteError),
    ),
)
def test_staging_permission_failure_is_classified_and_publishes_nothing(
    failed_role: str,
    expected_error: type[Exception],
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
    real_stage = BoundFileDestination.stage_bytes

    def fail_selected_stage(
        destination: BoundFileDestination,
        serialized: bytes,
    ) -> AbstractContextManager[destination_module.StagedFileWrite]:
        selected_path = report_path if failed_role == "report" else output_path
        if destination.requested_path == selected_path:
            permission_error = PermissionError(errno.EACCES, "permission denied")
            raise BoundFileDestinationError("permission denied") from permission_error
        return real_stage(destination, serialized)

    monkeypatch.setattr(BoundFileDestination, "stage_bytes", fail_selected_stage)

    with pytest.raises(expected_error, match="permission denied"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=io.BytesIO(),
        )

    assert not output_path.exists()
    assert not report_path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="requires unprivileged POSIX permission enforcement",
)
@pytest.mark.parametrize(
    ("failed_role", "expected_error"),
    (
        ("report", GenerationReportWriteError),
        ("output", GenerationDocumentWriteError),
    ),
)
def test_real_parent_permission_failure_publishes_nothing(
    failed_role: str,
    expected_error: type[Exception],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_parent = tmp_path / "output"
    report_parent = tmp_path / "report"
    output_parent.mkdir()
    report_parent.mkdir()
    output_path = output_parent / "vex.json"
    report_path = report_parent / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    selected_parent = report_parent if failed_role == "report" else output_parent
    selected_parent.chmod(0o500)
    try:
        with pytest.raises(expected_error, match=r"(?i)permission denied"):
            transaction.commit(
                _generation_result(monkeypatch),
                binary_stdout=io.BytesIO(),
            )
    finally:
        selected_parent.chmod(0o700)
        transaction.close()

    assert not output_path.exists()
    assert not report_path.exists()
    assert list(output_parent.glob(".vexcalibur-*.tmp")) == []
    assert list(report_parent.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_missing_binary_stdout_leaves_no_execution_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )

    with pytest.raises(GenerationDocumentWriteError, match="unavailable"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert not report_path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_output_commit_failure_leaves_no_execution_report(
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
    real_commit = destination_module.StagedFileWrite.commit

    def fail_output_commit(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        if staged.destination.requested_path == output_path:
            raise BoundFileDestinationError("output commit denied")
        real_commit(staged, destination_lock_held=destination_lock_held)

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "commit",
        fail_output_commit,
    )

    with pytest.raises(GenerationDocumentWriteError, match="output commit denied"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=io.BytesIO(),
        )

    assert not output_path.exists()
    assert not report_path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_intervening_report_is_removed_under_lock_before_output_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    output_path.write_bytes(b'{"message":"old"}\n')
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    real_acquire = generation_output_module.acquire_destination_locks
    real_commit = destination_module.StagedFileWrite.commit

    def publish_report_before_lock(
        destinations: tuple[BoundFileDestination | None, ...],
    ) -> AbstractContextManager[None]:
        report_path.write_bytes(b'{"concurrent":true}\n')
        return real_acquire(destinations)

    def fail_report_commit(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        if staged.destination.requested_path == report_path:
            raise BoundFileDestinationError("report commit denied")
        real_commit(staged, destination_lock_held=destination_lock_held)

    monkeypatch.setattr(
        generation_output_module,
        "acquire_destination_locks",
        publish_report_before_lock,
    )
    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "commit",
        fail_report_commit,
    )

    with pytest.raises(GenerationReportWriteError, match="report commit denied"):
        transaction.commit(
            _distinct_generation_result(monkeypatch, "new"),
            binary_stdout=None,
        )

    assert output_path.read_bytes() == b'{"message":"new"}\n'
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_locked_report_cleanup_failure_preserves_existing_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    previous_output = b'{"message":"old"}\n'
    output_path.write_bytes(previous_output)
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    real_remove = BoundFileDestination.remove_existing

    def fail_locked_report_cleanup(
        destination: BoundFileDestination,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        if destination.requested_path == report_path and destination_lock_held:
            raise BoundFileDestinationError("report cleanup denied")
        real_remove(
            destination,
            destination_lock_held=destination_lock_held,
        )

    monkeypatch.setattr(
        BoundFileDestination,
        "remove_existing",
        fail_locked_report_cleanup,
    )

    with pytest.raises(GenerationReportWriteError, match="report cleanup denied"):
        transaction.commit(
            _distinct_generation_result(monkeypatch, "new"),
            binary_stdout=None,
        )

    assert output_path.read_bytes() == previous_output
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_stdout_failure_leaves_no_execution_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class BrokenStdout:
        def write(self, value: bytes) -> int:
            raise OSError("stdout failed")

        def flush(self) -> None:
            raise AssertionError("flush must not follow a failed write")

    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )

    with pytest.raises(GenerationDocumentWriteError, match="stdout failed"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=BrokenStdout(),  # type: ignore[arg-type]
        )

    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_partial_stdout_failure_leaves_no_execution_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class PartialThenBrokenStdout:
        def __init__(self) -> None:
            self.content = bytearray()
            self.write_count = 0

        def write(self, value: bytes) -> int:
            self.write_count += 1
            if self.write_count > 1:
                raise OSError("stdout failed after a partial write")
            written = min(3, len(value))
            self.content.extend(value[:written])
            return written

        def flush(self) -> None:
            raise AssertionError("flush must not follow a failed write")

    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )
    stdout = PartialThenBrokenStdout()
    result = _generation_result(monkeypatch)

    with pytest.raises(GenerationDocumentWriteError, match="partial write"):
        transaction.commit(
            result,
            binary_stdout=stdout,  # type: ignore[arg-type]
        )

    assert bytes(stdout.content) == result.rendered_bytes[:3]
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_short_stdout_writes_are_completed_before_report_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ShortStdout:
        def __init__(self) -> None:
            self.content = bytearray()
            self.flushed = False

        def write(self, value: bytes) -> int:
            written = min(2, len(value))
            self.content.extend(value[:written])
            return written

        def flush(self) -> None:
            self.flushed = True

    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )
    assert transaction.report_destination is not None
    parent_descriptor = transaction.report_destination._parent_descriptor
    stdout = ShortStdout()
    result = _generation_result(monkeypatch)

    transaction.commit(
        result,
        binary_stdout=stdout,  # type: ignore[arg-type]
    )

    assert bytes(stdout.content) == result.rendered_bytes
    assert stdout.flushed is True
    assert report_path.exists()
    transaction.close()
    with pytest.raises(OSError):
        os.fstat(parent_descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_invalid_stdout_write_count_leaves_no_execution_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ZeroWriteStdout:
        def write(self, value: bytes) -> int:
            return 0

        def flush(self) -> None:
            raise AssertionError("flush must not follow an invalid write")

    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )
    assert transaction.report_destination is not None
    parent_descriptor = transaction.report_destination._parent_descriptor

    with pytest.raises(GenerationDocumentWriteError, match="invalid write count"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=ZeroWriteStdout(),  # type: ignore[arg-type]
        )

    assert not report_path.exists()
    transaction.close()
    with pytest.raises(OSError):
        os.fstat(parent_descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_blocked_stdout_holds_publication_lock_until_report_is_published(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    class BlockingStdout:
        def __init__(self) -> None:
            self.write_started = threading.Event()
            self.release_write = threading.Event()

        def write(self, value: bytes) -> int:
            self.write_started.set()
            if not self.release_write.wait(timeout=5):
                raise AssertionError("test did not release standard output")
            return len(value)

        def flush(self) -> None:
            return

    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )
    stdout = BlockingStdout()
    lock_attempted = threading.Event()
    errors: list[BaseException] = []
    real_flock = fcntl.flock

    def observe_lock(descriptor: int, operation: int) -> None:
        if operation & fcntl.LOCK_EX:
            lock_attempted.set()
        real_flock(descriptor, operation)

    def publish() -> None:
        try:
            transaction.commit(
                _generation_result(monkeypatch),
                binary_stdout=stdout,  # type: ignore[arg-type]
            )
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(fcntl, "flock", observe_lock)
    thread = threading.Thread(target=publish)
    thread.start()
    try:
        assert stdout.write_started.wait(timeout=5)
        assert lock_attempted.is_set()
        stdout.release_write.set()
        thread.join(timeout=5)
    finally:
        stdout.release_write.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert lock_attempted.is_set()
    assert report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_late_output_alias_is_removed_before_report_publication(
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
    real_commit = destination_module.StagedFileWrite.commit

    def commit_then_alias(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        real_commit(staged, destination_lock_held=destination_lock_held)
        if staged.destination.requested_path == output_path:
            report_path.hardlink_to(output_path)

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "commit",
        commit_then_alias,
    )

    with pytest.raises(GenerationReportWriteError, match="became an alias"):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,  # type: ignore[arg-type]
        )

    assert output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
@pytest.mark.parametrize("description", ["standard output", "standard error"])
def test_late_stream_alias_is_removed_before_report_publication(
    description: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    redirected_stream = tmp_path / "redirected-stream.log"
    redirected_stream.write_bytes(b"stream content")
    descriptor = os.open(redirected_stream, os.O_WRONLY)
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
        protected_descriptors=((descriptor, description),),
    )
    real_commit = destination_module.StagedFileWrite.commit

    def commit_then_alias(
        staged: destination_module.StagedFileWrite,
        *,
        destination_lock_held: bool = False,
    ) -> None:
        real_commit(staged, destination_lock_held=destination_lock_held)
        if staged.destination.requested_path == output_path:
            report_path.hardlink_to(redirected_stream)

    monkeypatch.setattr(
        destination_module.StagedFileWrite,
        "commit",
        commit_then_alias,
    )

    try:
        with pytest.raises(GenerationReportWriteError, match=f"redirected {description}"):
            transaction.commit(
                _generation_result(monkeypatch),
                binary_stdout=None,
            )
    finally:
        os.close(descriptor)

    assert output_path.exists()
    assert not report_path.exists()
    assert redirected_stream.read_bytes() == b"stream content"


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_output_directory_lock_failure_is_a_document_write_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    output_directory = tmp_path / "output"
    report_directory = tmp_path / "report"
    output_directory.mkdir()
    report_directory.mkdir()
    output_path = output_directory / "vex.json"
    report_path = report_directory / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    output_identity = (output_directory.stat().st_dev, output_directory.stat().st_ino)
    real_flock = fcntl.flock
    real_open_lock = lock_module._open_private_destination_lock
    lock_destinations: dict[int, tuple[int, int]] = {}

    def observe_open_lock(parent_descriptor: int) -> int:
        descriptor = real_open_lock(parent_descriptor)
        parent_metadata = os.fstat(parent_descriptor)
        lock_destinations[descriptor] = (parent_metadata.st_dev, parent_metadata.st_ino)
        return descriptor

    def fail_output_lock(descriptor: int, operation: int) -> None:
        if operation & fcntl.LOCK_EX and lock_destinations.get(descriptor) == output_identity:
            raise OSError("locking is unsupported")
        real_flock(descriptor, operation)

    monkeypatch.setattr(
        lock_module,
        "_open_private_destination_lock",
        observe_open_lock,
    )
    monkeypatch.setattr(fcntl, "flock", fail_output_lock)

    with pytest.raises(
        GenerationDocumentWriteError,
        match="could not lock the destination",
    ):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=io.BytesIO(),
        )

    assert not output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_report_directory_lock_failure_is_a_report_write_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=report_path,
        protected_paths=(),
    )

    def fail_lock(descriptor: int, operation: int) -> None:
        raise OSError("locking is unsupported")

    monkeypatch.setattr(fcntl, "flock", fail_lock)

    with pytest.raises(
        GenerationReportWriteError,
        match="could not lock the destination",
    ):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=io.BytesIO(),
        )

    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX report transaction")
def test_shared_directory_lock_failure_is_a_document_write_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "execution-report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )

    real_flock = fcntl.flock

    def fail_output_lock(descriptor: int, operation: int) -> None:
        if operation & fcntl.LOCK_EX:
            raise OSError("locking is unsupported")
        real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", fail_output_lock)

    with pytest.raises(
        GenerationDocumentWriteError,
        match="could not lock the destination",
    ):
        transaction.commit(
            _generation_result(monkeypatch),
            binary_stdout=None,
        )

    assert not output_path.exists()
    assert not report_path.exists()


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
