from __future__ import annotations

import copy
import dataclasses
import errno
import io
import os
import pickle
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

import vexcalibur
import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_filesystem as filesystem_module
import vexcalibur.execution_report_locks as lock_module
import vexcalibur.execution_report_staging as staging_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
    BoundFileDestinationError,
)
from vexcalibur.execution_report_lifecycle import DescriptorOwnership
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


def _result(monkeypatch: pytest.MonkeyPatch) -> GenerationResult:
    monkeypatch.setattr(vexcalibur, "__version__", "0.4.2.dev1")
    monkeypatch.setattr(
        "vexcalibur.generation_result.verify_source_checkout_version",
        lambda version: None,
    )
    monkeypatch.setattr(
        "vexcalibur.generation_result.importlib.metadata.version",
        lambda name: "0.4.2.dev1",
    )
    return GenerationResult(
        rendered_document='{"message":"complete"}\n',
        components=(),
        findings=(),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.SBOM_FILE,
            finding_source=FindingSourceCategory.LOCAL_FILE,
            output_format=ExecutionReportOutputFormat.CYCLONEDX,
        ),
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_bound_resources_cannot_be_duplicated(tmp_path: Path) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    try:
        with destination.stage_bytes(b"report") as staged:
            transaction = GenerationOutputTransaction.prepare(
                output_path=tmp_path / "vex.json",
                report_path=tmp_path / "transaction-report.json",
                protected_paths=(),
            )
            try:
                for resource in (destination, staged, transaction):
                    with pytest.raises(TypeError, match="cannot be copied"):
                        copy.copy(resource)
                    with pytest.raises(TypeError, match="cannot be copied"):
                        copy.deepcopy(resource)
                    if hasattr(copy, "replace"):
                        with pytest.raises(TypeError):
                            copy.replace(resource)
                    with pytest.raises(TypeError):
                        dataclasses.replace(resource)
                    with pytest.raises(TypeError, match="cannot be serialized"):
                        pickle.dumps(resource)
            finally:
                transaction.close()
    finally:
        destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_generation_output_transaction_is_single_use(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transaction = GenerationOutputTransaction.prepare(
        output_path=None,
        report_path=tmp_path / "report.json",
        protected_paths=(),
    )
    try:
        transaction.commit(
            _result(monkeypatch),
            binary_stdout=io.BytesIO(),
        )
        with pytest.raises(GenerationOutputError, match="already consumed"):
            transaction.commit(
                _result(monkeypatch),
                binary_stdout=io.BytesIO(),
            )
    finally:
        transaction.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_parent_directory_leaf_rejection_retains_no_descriptors() -> None:
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        pytest.skip("descriptor inventory requires procfs")
    retained_errors: list[BoundFileDestinationError] = []
    initial_descriptors = len(tuple(descriptor_directory.iterdir()))

    for _ in range(25):
        try:
            BoundFileDestination.prepare(Path(".."))
        except BoundFileDestinationError as exc:
            retained_errors.append(exc)

    assert len(retained_errors) == 25
    assert len(tuple(descriptor_directory.iterdir())) == initial_descriptors


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_interrupted_destination_close_never_closes_reused_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    owned_descriptor = destination._parent_descriptor
    replacement: list[int] = []
    real_close = os.close

    def close_then_reuse(descriptor: int) -> None:
        if descriptor != owned_descriptor:
            destination_module._close_descriptor_retryable(descriptor)
            return
        real_close(descriptor)
        replacement.append(os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
        assert replacement[-1] == owned_descriptor
        raise KeyboardInterrupt("synthetic post-close interruption")

    monkeypatch.setattr(staging_module, "_close_descriptor_retryable", close_then_reuse)
    try:
        with pytest.raises(KeyboardInterrupt, match="post-close interruption"):
            destination.close()

        assert not destination.closed
        assert destination._parent_descriptor_ownership is DescriptorOwnership.AMBIGUOUS
        assert destination._parent_descriptor == -1
        with pytest.raises(BoundFileDestinationError, match="release is ambiguous"):
            destination.close()
        os.fstat(replacement[0])
    finally:
        for descriptor in replacement:
            real_close(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_close_retains_ownership_when_pipe_allocation_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    descriptor = destination._parent_descriptor
    real_pipe = os.pipe

    def fail_pipe() -> tuple[int, int]:
        raise OSError(errno.EMFILE, "synthetic descriptor exhaustion")

    monkeypatch.setattr(filesystem_module.os, "pipe", fail_pipe)
    with pytest.raises(OSError, match="descriptor exhaustion"):
        destination.close()

    assert destination.closed is False
    assert destination._parent_descriptor == descriptor
    os.fstat(descriptor)

    monkeypatch.setattr(filesystem_module.os, "pipe", real_pipe)
    destination.close()
    assert destination.closed
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
@pytest.mark.parametrize(
    "failure",
    (
        KeyboardInterrupt("synthetic preflight interruption"),
        OSError(errno.ENOMEM, "synthetic preflight resource failure"),
    ),
)
def test_destination_close_retains_ownership_when_preflight_fails(
    failure: BaseException,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    descriptor = destination._parent_descriptor
    real_fstat = filesystem_module.os.fstat
    failed = False

    def fail_preflight(candidate: int) -> os.stat_result:
        nonlocal failed
        if candidate == descriptor and not failed:
            failed = True
            raise failure
        return real_fstat(candidate)

    monkeypatch.setattr(filesystem_module.os, "fstat", fail_preflight)
    with pytest.raises(type(failure), match="preflight"):
        destination.close()

    assert destination.closed is False
    assert destination._parent_descriptor == descriptor
    real_fstat(descriptor)

    monkeypatch.setattr(filesystem_module.os, "fstat", real_fstat)
    destination.close()
    assert destination.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
@pytest.mark.parametrize(
    ("owner_kind", "attribute"),
    (
        ("staged", "temporary_fd"),
        ("staged", "parent_fd"),
        ("rollback", "published_fd"),
        ("rollback", "parent_fd"),
        ("rollback", "lock_fd"),
    ),
)
def test_interrupted_staging_owner_close_never_closes_reused_descriptor(
    owner_kind: str,
    attribute: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    manager = destination.stage_bytes(b"report")
    staged = manager.__enter__()
    owner = staged if owner_kind == "staged" else staged._prepare_rollback()
    owned_descriptor = getattr(owner, attribute)
    replacement: list[int] = []
    real_release = staging_module._close_descriptor_retryable
    real_close = os.close
    if attribute in {"temporary_fd", "published_fd"}:
        replacement_path = tmp_path / staged.temporary_name
    elif attribute == "lock_fd":
        replacement_path = tmp_path / lock_module.LOCK_DIRECTORY_NAME / lock_module.LOCK_FILE_NAME
    else:
        replacement_path = tmp_path
    replacement_flags = os.O_RDONLY
    if attribute == "parent_fd":
        replacement_flags |= os.O_DIRECTORY
    replacement_source = os.open(replacement_path, replacement_flags)

    def close_then_reuse(descriptor: int) -> object:
        if descriptor != owned_descriptor:
            return real_release(descriptor)
        real_close(descriptor)
        replacement.append(os.dup2(replacement_source, descriptor))
        assert replacement[-1] == owned_descriptor
        raise KeyboardInterrupt("synthetic post-close interruption")

    monkeypatch.setattr(
        staging_module,
        "_close_descriptor_retryable",
        close_then_reuse,
    )
    try:
        with pytest.raises(KeyboardInterrupt, match="post-close interruption"):
            owner.close()

        assert getattr(owner, attribute) == -1
        ownership = getattr(owner, f"_{attribute}_ownership")
        assert ownership is DescriptorOwnership.AMBIGUOUS
        with pytest.raises(BoundFileDestinationError, match="release is ambiguous"):
            owner.close()
        os.fstat(replacement[0])
    finally:
        monkeypatch.setattr(
            staging_module,
            "_close_descriptor_retryable",
            real_release,
        )
        if owner_kind == "rollback":
            manager.__exit__(None, None, None)
        else:
            with pytest.raises(BoundFileDestinationError, match="release is ambiguous"):
                manager.__exit__(None, None, None)
        destination.close()
        for descriptor in replacement:
            real_close(descriptor)
        real_close(replacement_source)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
@pytest.mark.parametrize(
    ("owner_kind", "failure_call", "retained_attribute"),
    (
        ("staged", 1, "temporary_fd"),
        ("staged", 2, "parent_fd"),
        ("rollback", 1, "published_fd"),
        ("rollback", 2, "parent_fd"),
    ),
)
def test_staging_owner_close_retains_descriptor_when_pipe_allocation_fails(
    owner_kind: str,
    failure_call: int,
    retained_attribute: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    manager = destination.stage_bytes(b"report")
    staged = manager.__enter__()
    owner = staged if owner_kind == "staged" else staged._prepare_rollback()
    retained_descriptor = getattr(owner, retained_attribute)
    real_pipe = os.pipe
    calls = 0

    def fail_selected_pipe() -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise OSError(errno.EMFILE, "synthetic descriptor exhaustion")
        return real_pipe()

    monkeypatch.setattr(filesystem_module.os, "pipe", fail_selected_pipe)
    try:
        with pytest.raises(OSError, match="descriptor exhaustion"):
            owner.close()

        assert owner.closed is False
        assert getattr(owner, retained_attribute) == retained_descriptor
        os.fstat(retained_descriptor)

        monkeypatch.setattr(filesystem_module.os, "pipe", real_pipe)
        owner.close()
        assert owner.closed
        with pytest.raises(OSError):
            os.fstat(retained_descriptor)
    finally:
        monkeypatch.setattr(filesystem_module.os, "pipe", real_pipe)
        owner.close()
        manager.__exit__(None, None, None)
        destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_prepare_closes_destination_when_cleanup_registration_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[BoundFileDestination] = []
    real_prepare = BoundFileDestination.prepare.__func__

    def observe_prepare(
        cls: type[BoundFileDestination],
        path: Path,
        **kwargs: object,
    ) -> BoundFileDestination:
        destination = real_prepare(cls, path, **kwargs)
        observed.append(destination)
        return destination

    def cancel_registration(
        stack: ExitStack,
        callback: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        del stack, callback, args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(BoundFileDestination, "prepare", classmethod(observe_prepare))
    monkeypatch.setattr(ExitStack, "callback", cancel_registration)

    with pytest.raises(KeyboardInterrupt):
        GenerationOutputTransaction.prepare(
            output_path=tmp_path / "vex.json",
            report_path=tmp_path / "report.json",
            protected_paths=(),
        )

    assert len(observed) == 1
    with pytest.raises(OSError):
        os.fstat(observed[0]._parent_descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_rollback_acquisition_closes_descriptor_when_adoption_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    acquired: list[int] = []
    real_adopt = staging_module._adopt_owned_descriptor

    def interrupt_parent_adoption(
        owner: object,
        attribute: str,
        descriptor: int,
    ) -> None:
        if attribute == "parent_fd":
            acquired.append(descriptor)
            raise KeyboardInterrupt("pre-adoption interruption")
        real_adopt(owner, attribute, descriptor)

    monkeypatch.setattr(
        staging_module,
        "_adopt_owned_descriptor",
        interrupt_parent_adoption,
    )

    with destination.stage_bytes(b"report") as staged:
        staged.commit()
        with pytest.raises(KeyboardInterrupt, match="pre-adoption interruption"):
            staged.retain_rollback()

    assert len(acquired) == 1
    with pytest.raises(OSError):
        os.fstat(acquired[0])
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_lock_order_is_independent_of_output_and_report_roles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    first = BoundFileDestination.prepare(first_directory / "one.json")
    second = BoundFileDestination.prepare(second_directory / "two.json")
    observed: list[tuple[int, int]] = []

    @contextmanager
    def observe_lock(parent_descriptor: int):
        metadata = os.fstat(parent_descriptor)
        observed.append((metadata.st_dev, metadata.st_ino))
        yield parent_descriptor

    monkeypatch.setattr(lock_module, "_exclusive_destination_lock", observe_lock)
    try:
        with lock_module.acquire_destination_locks((first, second)):
            pass
        forward = tuple(observed)
        observed.clear()
        with lock_module.acquire_destination_locks((second, first)):
            pass
        reverse = tuple(observed)
    finally:
        first.close()
        second.close()

    assert forward == reverse == tuple(sorted(forward))


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_during_second_lock_releases_the_first(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    first = BoundFileDestination.prepare(first_directory / "one.json")
    second = BoundFileDestination.prepare(second_directory / "two.json")
    active: set[tuple[int, int]] = set()
    attempts = 0
    real_lock = lock_module._exclusive_destination_lock

    @contextmanager
    def cancel_second_lock(parent_descriptor: int):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise KeyboardInterrupt
        metadata = os.fstat(parent_descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        with real_lock(parent_descriptor):
            active.add(identity)
            try:
                yield parent_descriptor
            finally:
                active.remove(identity)

    monkeypatch.setattr(
        lock_module,
        "_exclusive_destination_lock",
        cancel_second_lock,
    )
    try:
        with (
            pytest.raises(KeyboardInterrupt),
            lock_module.acquire_destination_locks((first, second)),
        ):
            pass
    finally:
        first.close()
        second.close()

    assert attempts == 2
    assert active == set()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_one_parent_lock_coordinates_raw_leaf_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = BoundFileDestination.prepare(Path(os.fsdecode(os.fsencode(tmp_path) + b"/one-\xff")))
    second = BoundFileDestination.prepare(Path(os.fsdecode(os.fsencode(tmp_path) + b"/two-\xfe")))
    lock_calls = 0

    @contextmanager
    def observe_lock(parent_descriptor: int):
        nonlocal lock_calls
        os.fstat(parent_descriptor)
        lock_calls += 1
        yield parent_descriptor

    monkeypatch.setattr(lock_module, "_exclusive_destination_lock", observe_lock)
    try:
        with lock_module.acquire_destination_locks((first, second)):
            pass
    finally:
        first.close()
        second.close()

    assert lock_calls == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_unlock_cancellation_removes_the_published_success_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    output_path = tmp_path / "vex.json"
    report_path = tmp_path / "report.json"
    transaction = GenerationOutputTransaction.prepare(
        output_path=output_path,
        report_path=report_path,
        protected_paths=(),
    )
    real_flock = fcntl.flock
    cancelled = False

    def cancel_unlock(descriptor: int, operation: int) -> None:
        nonlocal cancelled
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN and not cancelled:
            cancelled = True
            raise KeyboardInterrupt

    monkeypatch.setattr(fcntl, "flock", cancel_unlock)

    with pytest.raises(KeyboardInterrupt):
        transaction.commit(
            _result(monkeypatch),
            binary_stdout=io.BytesIO(),
        )

    assert cancelled
    assert output_path.exists()
    assert not report_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_direct_write_unlock_cancellation_removes_published_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import fcntl

    path = tmp_path / "report.json"
    destination = BoundFileDestination.prepare(path)
    real_flock = fcntl.flock
    cancelled = False

    def cancel_unlock(descriptor: int, operation: int) -> None:
        nonlocal cancelled
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_UN and not cancelled:
            cancelled = True
            raise KeyboardInterrupt

    monkeypatch.setattr(fcntl, "flock", cancel_unlock)
    try:
        with destination.stage_bytes(b"report") as staged, pytest.raises(KeyboardInterrupt):
            staged.commit()
    finally:
        destination.close()

    assert cancelled
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_post_fsync_mode_change_removes_the_published_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "report.json"
    destination = BoundFileDestination.prepare(path)
    real_fsync = destination_module.os.fsync
    changed = False

    try:
        with destination.stage_bytes(b"report") as staged:

            def change_mode_after_directory_fsync(descriptor: int) -> None:
                nonlocal changed
                real_fsync(descriptor)
                if descriptor == staged.parent_fd and not changed:
                    changed = True
                    path.chmod(0o644)

            monkeypatch.setattr(
                destination_module.os,
                "fsync",
                change_mode_after_directory_fsync,
            )
            with pytest.raises(BoundFileDestinationError, match="published file changed"):
                staged.commit()
    finally:
        destination.close()

    assert changed
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_post_fsync_same_mode_replacement_is_preserved_and_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "report.json"
    replacement = tmp_path / "replacement.json"
    destination = BoundFileDestination.prepare(path)
    real_fsync = destination_module.os.fsync
    replaced = False

    try:
        with destination.stage_bytes(b"report") as staged:

            def replace_after_directory_fsync(descriptor: int) -> None:
                nonlocal replaced
                real_fsync(descriptor)
                if descriptor == staged.parent_fd and not replaced:
                    replaced = True
                    replacement.write_bytes(b"replacement")
                    replacement.chmod(0o600)
                    replacement.replace(path)

            monkeypatch.setattr(
                destination_module.os,
                "fsync",
                replace_after_directory_fsync,
            )
            with pytest.raises(BoundFileDestinationError, match="published file changed"):
                staged.commit()
    finally:
        destination.close()

    assert replaced
    assert path.read_bytes() == b"replacement"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_coordination_namespace_is_reserved_through_directory_alias(
    tmp_path: Path,
) -> None:
    lock_directory = tmp_path / destination_module.LOCK_DIRECTORY_NAME
    lock_directory.mkdir(mode=0o700)
    nested = lock_directory / "nested"
    nested.mkdir()
    alias = tmp_path / "lock-alias"
    alias.symlink_to(lock_directory, target_is_directory=True)

    for parent in (lock_directory, nested, alias, alias / "nested"):
        with pytest.raises(BoundFileDestinationError, match=r"directory.*reserved"):
            BoundFileDestination.prepare(
                parent / destination_module.LOCK_FILE_NAME,
            )


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_lock_alias_is_rejected_after_lock_acquisition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination_path = tmp_path / "report.json"
    destination = BoundFileDestination.prepare(destination_path)
    real_lock = lock_module._exclusive_destination_lock

    @contextmanager
    def alias_acquired_lock(parent_descriptor: int):
        with real_lock(parent_descriptor) as lock_descriptor:
            lock_path = (
                tmp_path
                / destination_module.LOCK_DIRECTORY_NAME
                / destination_module.LOCK_FILE_NAME
            )
            destination_path.hardlink_to(lock_path)
            yield lock_descriptor

    monkeypatch.setattr(
        lock_module,
        "_exclusive_destination_lock",
        alias_acquired_lock,
    )
    try:
        with (
            pytest.raises(
                destination_module.DestinationLockError,
                match="coordination lock",
            ),
            lock_module.acquire_destination_locks((destination,)),
        ):
            pass
    finally:
        destination.close()

    assert destination_path.samefile(
        tmp_path / destination_module.LOCK_DIRECTORY_NAME / destination_module.LOCK_FILE_NAME
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_lock_directory_replacement_after_lock_fchmod_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    lock_directory = tmp_path / destination_module.LOCK_DIRECTORY_NAME
    moved_directory = tmp_path / "moved-lock-directory"
    real_fchmod = destination_module.os.fchmod
    real_open = destination_module.os.open
    lock_descriptor = -1
    replaced = False

    def observe_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal lock_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == destination_module.LOCK_FILE_NAME:
            lock_descriptor = descriptor
        return descriptor

    def replace_after_lock_fchmod(descriptor: int, mode: int) -> None:
        nonlocal replaced
        real_fchmod(descriptor, mode)
        if descriptor == lock_descriptor and not replaced:
            replaced = True
            lock_directory.rename(moved_directory)
            lock_directory.mkdir(mode=0o700)

    monkeypatch.setattr(destination_module.os, "open", observe_open)
    monkeypatch.setattr(destination_module.os, "fchmod", replace_after_lock_fchmod)

    with pytest.raises(BoundFileDestinationError, match="could not open"):
        destination.write_bytes(b"report")

    assert replaced
    assert not (tmp_path / "report.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_late_lock_owner_change_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    real_open = destination_module.os.open
    real_fstat = destination_module.os.fstat
    lock_descriptor = -1
    lock_stat_calls = 0

    def observe_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal lock_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == destination_module.LOCK_FILE_NAME:
            lock_descriptor = descriptor
        return descriptor

    def change_owner_on_second_check(descriptor: int) -> os.stat_result:
        nonlocal lock_stat_calls
        metadata = real_fstat(descriptor)
        if descriptor != lock_descriptor:
            return metadata
        lock_stat_calls += 1
        if lock_stat_calls == 2:
            values = list(metadata)
            values[4] = metadata.st_uid + 1
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(destination_module.os, "open", observe_open)
    monkeypatch.setattr(destination_module.os, "fstat", change_owner_on_second_check)

    with pytest.raises(BoundFileDestinationError, match="could not open"):
        destination.write_bytes(b"report")

    assert lock_stat_calls >= 2
    assert not (tmp_path / "report.json").exists()
