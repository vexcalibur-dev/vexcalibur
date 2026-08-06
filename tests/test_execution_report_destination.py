from __future__ import annotations

import os
import signal
from pathlib import Path

import pytest

import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_staging as staging_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
    BoundFileDestinationError,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_replaces_stale_file_with_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.json"
    path.write_text('{"stale":true}\n', encoding="utf-8")

    destination = BoundFileDestination.prepare(path, remove_existing=True)
    assert not path.exists()
    destination.write_bytes(b'{"schema_version":1}\n')

    assert path.read_bytes() == b'{"schema_version":1}\n'
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_mode_is_exact_under_restrictive_umask(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.json"
    previous_umask = os.umask(0o777)
    try:
        BoundFileDestination.prepare(path).write_bytes(b"report")
    finally:
        os.umask(previous_umask)

    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == b"report"
    lock_directory = tmp_path / destination_module.LOCK_DIRECTORY_NAME
    assert lock_directory.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_symlink_loop_parent_is_a_controlled_destination_error(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second, target_is_directory=True)
    second.symlink_to(first, target_is_directory=True)

    with pytest.raises(
        BoundFileDestinationError,
        match="could not resolve destination parent directory",
    ):
        BoundFileDestination.prepare(first / "report.json")


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_parent_preparation_preserves_primary_and_descriptor_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_descriptor = os.open(tmp_path, os.O_RDONLY)
    cleanup_failure = OSError("parent descriptor close failed")

    def return_parent_descriptor(*args: object, **kwargs: object) -> int:
        return parent_descriptor

    def fail_parent_stat(descriptor: int) -> os.stat_result:
        raise OSError("parent stat failed")

    def fail_descriptor_close(descriptor: int) -> None:
        raise cleanup_failure

    monkeypatch.setattr(destination_module.os, "open", return_parent_descriptor)
    monkeypatch.setattr(
        destination_module.os,
        "fstat",
        fail_parent_stat,
    )
    monkeypatch.setattr(
        destination_module,
        "_close_descriptor",
        fail_descriptor_close,
    )

    try:
        with pytest.raises(BoundFileDestinationError, match="could not open") as captured:
            BoundFileDestination.prepare(tmp_path / "report.json")
    finally:
        os.close(parent_descriptor)

    assert captured.value.__cause__ is not None
    assert str(captured.value.__cause__) == "parent stat failed"
    assert captured.value.vexcalibur_cleanup_failures == (cleanup_failure,)  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_preparation_preserves_primary_and_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_failure = OSError("destination close failed")
    real_close = BoundFileDestination.close

    def fail_verification(destination: BoundFileDestination) -> None:
        raise OSError("destination verification failed")

    def close_then_fail(destination: BoundFileDestination) -> None:
        real_close(destination)
        raise cleanup_failure

    monkeypatch.setattr(BoundFileDestination, "verify_replaceable_leaf", fail_verification)
    monkeypatch.setattr(BoundFileDestination, "close", close_then_fail)

    with pytest.raises(OSError, match="destination verification failed") as captured:
        BoundFileDestination.prepare(tmp_path / "report.json")

    assert captured.value.vexcalibur_cleanup_failures == (cleanup_failure,)  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_replace_failure_leaves_no_destination_or_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    path.write_text('{"stale":true}\n', encoding="utf-8")
    destination = BoundFileDestination.prepare(path, remove_existing=True)

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(destination_module.os, "replace", fail_replace)

    with pytest.raises(BoundFileDestinationError, match="replace failed"):
        destination.write_bytes(b"replacement")

    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_during_staging_fsync_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    parent_descriptor = destination._parent_descriptor

    def cancel_fsync(descriptor: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(destination_module.os, "fsync", cancel_fsync)

    with pytest.raises(KeyboardInterrupt):
        destination.write_bytes(b"private report")

    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []
    with pytest.raises(OSError):
        os.fstat(parent_descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_during_temporary_file_setup_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    parent_descriptor = destination._parent_descriptor

    def cancel_fchmod(descriptor: int, mode: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(destination_module.os, "fchmod", cancel_fchmod)

    with pytest.raises(KeyboardInterrupt):
        destination.write_bytes(b"private report")

    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []
    with pytest.raises(OSError):
        os.fstat(parent_descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_pending_sigint_after_temporary_open_has_a_cleanup_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    real_open = staging_module.os.open
    interrupted = False

    def open_then_interrupt(*args: object, **kwargs: object) -> int:
        nonlocal interrupted
        descriptor = real_open(*args, **kwargs)
        if not interrupted:
            interrupted = True
            os.kill(os.getpid(), signal.SIGINT)
        return descriptor

    monkeypatch.setattr(staging_module.os, "open", open_then_interrupt)

    with pytest.raises(KeyboardInterrupt):
        destination.write_bytes(b"private report")

    assert interrupted
    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []
    assert destination.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
@pytest.mark.parametrize(
    "operation",
    ("remove_existing", "verify_replaceable_leaf", "stage_bytes"),
)
def test_pending_sigint_after_parent_open_closes_descriptor(
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    path.write_bytes(b"stale report")
    destination = BoundFileDestination.prepare(path)
    real_open_parent = BoundFileDestination._open_parent
    observed_descriptors: list[int] = []

    def open_then_interrupt(selected: BoundFileDestination) -> int:
        descriptor = real_open_parent(selected)
        observed_descriptors.append(descriptor)
        os.kill(os.getpid(), signal.SIGINT)
        return descriptor

    monkeypatch.setattr(BoundFileDestination, "_open_parent", open_then_interrupt)

    try:
        with pytest.raises(KeyboardInterrupt):
            if operation == "stage_bytes":
                with destination.stage_bytes(b"private report"):
                    pytest.fail("staging unexpectedly reached the context body")
            else:
                getattr(destination, operation)()

        assert len(observed_descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(observed_descriptors[0])
    finally:
        destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_temporary_setup_preserves_primary_and_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "execution-report.json")

    def fail_fchmod(descriptor: int, mode: int) -> None:
        raise OSError("temporary mode failed")

    monkeypatch.setattr(destination_module.os, "fchmod", fail_fchmod)
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        lambda **kwargs: False,
    )

    with pytest.raises(BoundFileDestinationError, match="temporary mode failed") as captured:
        destination.write_bytes(b"private report")

    assert captured.value.__cause__ is not None
    assert str(captured.value.__cause__) == "temporary mode failed"
    (cleanup_failure,) = captured.value.vexcalibur_cleanup_failures  # type: ignore[attr-defined]
    assert isinstance(cleanup_failure, BoundFileDestinationError)
    assert str(cleanup_failure) == "could not remove the staged temporary file"
    assert len(list(tmp_path.glob(".vexcalibur-*.tmp"))) == 1
    assert destination.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_during_temporary_file_handoff_closes_the_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    observed_descriptors: list[int] = []

    def cancel_handoff(descriptor: int, name: str) -> tuple[int, str]:
        del name
        observed_descriptors.append(descriptor)
        raise KeyboardInterrupt("temporary file handoff interrupted")

    monkeypatch.setattr(
        staging_module,
        "_temporary_file_result",
        cancel_handoff,
    )

    with pytest.raises(
        KeyboardInterrupt,
        match="temporary file handoff interrupted",
    ):
        destination.write_bytes(b"private report")

    assert len(observed_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(observed_descriptors[0])
    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_during_staging_cleanup_closes_all_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    bound_parent_descriptor = destination._parent_descriptor
    staging_descriptors: list[int] = []
    real_create = BoundFileDestination._create_temporary_file

    def observe_temporary_file(
        self: BoundFileDestination,
        parent_descriptor: int,
    ) -> tuple[int, str]:
        result = real_create(self, parent_descriptor)
        staging_descriptors.extend((parent_descriptor, result[0]))
        return result

    def fail_fsync(descriptor: int) -> None:
        raise OSError("staging fsync failed")

    cleanup_failure = KeyboardInterrupt("synthetic cleanup cancellation")

    def cancel_cleanup(*args: object, **kwargs: object) -> None:
        raise cleanup_failure

    monkeypatch.setattr(
        BoundFileDestination,
        "_create_temporary_file",
        observe_temporary_file,
    )
    monkeypatch.setattr(destination_module.os, "fsync", fail_fsync)
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        cancel_cleanup,
    )

    with pytest.raises(BoundFileDestinationError, match="staging fsync failed") as captured:
        destination.write_bytes(b"private report")

    assert captured.value.__cause__ is not None
    assert str(captured.value.__cause__) == "staging fsync failed"
    assert captured.value.vexcalibur_cleanup_failures == (cleanup_failure,)  # type: ignore[attr-defined]
    for descriptor in (*staging_descriptors, bound_parent_descriptor):
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_failed_staged_removal_is_retained_as_a_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)

    def fail_fsync(descriptor: int) -> None:
        raise OSError("staging fsync failed")

    monkeypatch.setattr(destination_module.os, "fsync", fail_fsync)
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        lambda **kwargs: False,
    )

    with pytest.raises(BoundFileDestinationError, match="staging fsync failed") as captured:
        destination.write_bytes(b"private report")

    (cleanup_failure,) = captured.value.vexcalibur_cleanup_failures  # type: ignore[attr-defined]
    assert isinstance(cleanup_failure, BoundFileDestinationError)
    assert str(cleanup_failure) == "could not remove the staged temporary file"
    assert len(list(tmp_path.glob(".vexcalibur-*.tmp"))) == 1
    assert destination.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_close_failure_appends_to_staging_cleanup_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "execution-report.json")
    staging_cleanup_failure = BoundFileDestinationError("staging cleanup failed")
    destination_cleanup_failure = BoundFileDestinationError("destination cleanup failed")
    real_close = BoundFileDestination.close

    def fail_fsync(descriptor: int) -> None:
        raise OSError("staging fsync failed")

    def fail_staging_cleanup(*args: object, **kwargs: object) -> None:
        raise staging_cleanup_failure

    def close_then_fail(selected: BoundFileDestination) -> None:
        real_close(selected)
        if selected is destination:
            raise destination_cleanup_failure

    monkeypatch.setattr(destination_module.os, "fsync", fail_fsync)
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        fail_staging_cleanup,
    )
    monkeypatch.setattr(BoundFileDestination, "close", close_then_fail)

    with pytest.raises(BoundFileDestinationError, match="staging fsync failed") as captured:
        destination.write_bytes(b"private report")

    assert captured.value.vexcalibur_cleanup_failures == (  # type: ignore[attr-defined]
        staging_cleanup_failure,
        destination_cleanup_failure,
    )
    assert destination.closed


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_finalizer_bypasses_stateful_close_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "execution-report.json")
    descriptor = destination._parent_descriptor

    def unexpected_close(_destination: BoundFileDestination) -> None:
        raise AssertionError("finalizer dispatched through close")

    monkeypatch.setattr(BoundFileDestination, "close", unexpected_close)

    destination.__del__()

    assert destination.closed
    assert destination._parent_descriptor == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_stage_scope_cancellation_removes_staged_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    staging_descriptors: tuple[int, int] = ()
    with pytest.raises(KeyboardInterrupt), destination.stage_bytes(b"private report") as staged:
        staging_descriptors = (staged.parent_fd, staged.temporary_fd)
        raise KeyboardInterrupt

    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []
    for descriptor in staging_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_stage_scope_preserves_body_failure_when_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "execution-report.json")
    primary_failure = KeyboardInterrupt("stage body failed")
    cleanup_failure = BoundFileDestinationError("stage close failed")
    real_close = staging_module.StagedFileWrite.close

    def close_then_fail(staged: staging_module.StagedFileWrite) -> None:
        real_close(staged)
        raise cleanup_failure

    monkeypatch.setattr(staging_module.StagedFileWrite, "close", close_then_fail)

    with (
        pytest.raises(KeyboardInterrupt) as captured,
        destination.stage_bytes(b"private report"),
    ):
        raise primary_failure

    assert captured.value is primary_failure
    assert captured.value.vexcalibur_cleanup_failures == (cleanup_failure,)  # type: ignore[attr-defined]
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_stage_scope_exit_removes_private_bytes(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    with destination.stage_bytes(b"private report") as staged:
        parent_descriptor = staged.parent_fd
        temporary_descriptor = staged.temporary_fd

    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []
    for descriptor in (parent_descriptor, temporary_descriptor):
        with pytest.raises(OSError):
            os.fstat(descriptor)
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_parent_swap_cannot_redirect_destination(
    tmp_path: Path,
) -> None:
    report_parent = tmp_path / "report-parent"
    report_parent.mkdir()
    moved_parent = tmp_path / "moved-report-parent"
    redirected_parent = tmp_path / "redirected-parent"
    redirected_parent.mkdir()
    victim = redirected_parent / "execution-report.json"
    victim.write_bytes(b"original bytes")
    destination = BoundFileDestination.prepare(
        report_parent / victim.name,
        protected_paths=(victim,),
        remove_existing=True,
    )

    report_parent.rename(moved_parent)
    report_parent.symlink_to(redirected_parent, target_is_directory=True)

    with pytest.raises(
        BoundFileDestinationError,
        match="parent directory changed",
    ):
        destination.write_bytes(b"replacement")

    assert victim.read_bytes() == b"original bytes"
    assert not (moved_parent / victim.name).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_intermediate_parent_symlink_retarget_cannot_redirect_destination(
    tmp_path: Path,
) -> None:
    first_parent = tmp_path / "first"
    first_parent.mkdir()
    second_parent = tmp_path / "second"
    second_parent.mkdir()
    parent_link = tmp_path / "current"
    parent_link.symlink_to(first_parent, target_is_directory=True)
    destination = BoundFileDestination.prepare(parent_link / "report.json")

    with destination.stage_bytes(b"replacement") as staged:
        parent_link.unlink()
        parent_link.symlink_to(second_parent, target_is_directory=True)
        with pytest.raises(BoundFileDestinationError, match="parent directory changed"):
            staged.commit()

    assert not (first_parent / "report.json").exists()
    assert not (second_parent / "report.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_retargeted_parent_alias_check_uses_bound_directory(
    tmp_path: Path,
) -> None:
    original_parent = tmp_path / "original"
    original_parent.mkdir()
    moved_parent = tmp_path / "moved"
    decoy_parent = tmp_path / "decoy"
    parent_link = tmp_path / "current"
    parent_link.symlink_to(original_parent, target_is_directory=True)
    destination = BoundFileDestination.prepare(parent_link / "report.json")
    redirected_stdout = tmp_path / "stdout.json"
    redirected_stdout.write_bytes(b"stdout")

    original_parent.rename(moved_parent)
    decoy_parent.mkdir()
    original_parent.symlink_to(decoy_parent, target_is_directory=True)
    parent_link.unlink()
    parent_link.symlink_to(moved_parent, target_is_directory=True)
    (moved_parent / "report.json").hardlink_to(redirected_stdout)

    descriptor = os.open(redirected_stdout, os.O_WRONLY)
    try:
        assert destination.aliases_descriptor(descriptor)
    finally:
        os.close(descriptor)
        destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_live_parent_descriptor_rejects_a_precreated_replacement(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    destination = BoundFileDestination.prepare(parent / "report.json")
    retained_stat = os.fstat(destination._parent_descriptor)
    replacement_stat = replacement.stat()
    assert (replacement_stat.st_dev, replacement_stat.st_ino) != (
        retained_stat.st_dev,
        retained_stat.st_ino,
    )

    parent.rmdir()
    replacement.rename(parent)

    with pytest.raises(BoundFileDestinationError, match="parent directory changed"):
        destination.write_bytes(b"replacement")

    assert not (parent / "report.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_replaced_staging_entry_is_not_published(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.json"
    attacker_file = tmp_path / "attacker.json"
    attacker_file.write_bytes(b"attacker controlled")
    destination = BoundFileDestination.prepare(path)

    with destination.stage_bytes(b"expected report") as staged:
        os.unlink(staged.temporary_name, dir_fd=staged.parent_fd)
        os.symlink(
            attacker_file,
            staged.temporary_name,
            dir_fd=staged.parent_fd,
        )

        with pytest.raises(BoundFileDestinationError, match="staged file changed"):
            staged.commit()

    destination.close()
    assert not path.exists()
    assert attacker_file.read_bytes() == b"attacker controlled"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_symlink_destination_replaces_only_the_link(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"protected target")
    path = tmp_path / "execution-report.json"
    path.symlink_to(target)

    BoundFileDestination.prepare(path, remove_existing=True).write_bytes(b"report")

    assert path.read_bytes() == b"report"
    assert not path.is_symlink()
    assert target.read_bytes() == b"protected target"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_hardlink_destination_replaces_only_the_named_link(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"protected target")
    path = tmp_path / "execution-report.json"
    path.hardlink_to(target)

    BoundFileDestination.prepare(path, remove_existing=True).write_bytes(b"report")

    assert path.read_bytes() == b"report"
    assert target.read_bytes() == b"protected target"
    assert path.stat().st_ino != target.stat().st_ino


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_staged_file_mode_change_prevents_publication(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)

    with destination.stage_bytes(b"expected report") as staged:
        os.fchmod(staged.temporary_fd, 0o644)

        with pytest.raises(BoundFileDestinationError, match="mode changed"):
            staged.commit()

    destination.close()
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_post_replace_mode_change_removes_unverified_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    real_replace = destination_module.os.replace

    def replace_then_change_mode(*args: object, **kwargs: object) -> None:
        real_replace(*args, **kwargs)
        path.chmod(0o644)

    monkeypatch.setattr(destination_module.os, "replace", replace_then_change_mode)

    with pytest.raises(BoundFileDestinationError, match="published file changed"):
        destination.write_bytes(b"expected report")

    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_post_replace_directory_fsync_failure_fails_and_removes_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path, remove_existing=True)
    real_fsync = destination_module.os.fsync
    calls = 0

    def fail_second_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync failed")
        real_fsync(descriptor)

    monkeypatch.setattr(destination_module.os, "fsync", fail_second_fsync)

    with pytest.raises(BoundFileDestinationError, match="directory fsync failed"):
        destination.write_bytes(b"replacement")

    assert calls == 3
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_after_replace_removes_unverified_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    real_replace = destination_module.os.replace

    def replace_then_cancel(*args: object, **kwargs: object) -> None:
        real_replace(*args, **kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(destination_module.os, "replace", replace_then_cancel)

    with pytest.raises(KeyboardInterrupt):
        destination.write_bytes(b"replacement")

    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_interrupted_rollback_retries_without_losing_cleanup_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    real_fsync = staging_module.os.fsync
    real_remove = staging_module._remove_matching_destination
    fsync_calls = 0
    rollback_interrupted = False

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("directory fsync failed")
        real_fsync(descriptor)

    def interrupt_first_rollback(*args: object, **kwargs: object) -> bool:
        nonlocal rollback_interrupted
        if not rollback_interrupted:
            rollback_interrupted = True
            raise KeyboardInterrupt("rollback interrupted")
        return real_remove(*args, **kwargs)

    monkeypatch.setattr(staging_module.os, "fsync", fail_directory_fsync)
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        interrupt_first_rollback,
    )

    with pytest.raises(KeyboardInterrupt, match="rollback interrupted"):
        destination.write_bytes(b"replacement")

    assert rollback_interrupted
    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_cancellation_during_rollback_acquisition_closes_retained_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    real_create = staging_module.PublishedFileRollback._create.__func__
    real_dup = staging_module.os.dup
    observed_rollbacks: list[staging_module.PublishedFileRollback] = []
    duplicate_calls = 0

    def observe_guard(
        cls: type[staging_module.PublishedFileRollback],
    ) -> staging_module.PublishedFileRollback:
        rollback = real_create(cls)
        observed_rollbacks.append(rollback)
        return rollback

    def cancel_second_duplicate(descriptor: int) -> int:
        nonlocal duplicate_calls
        duplicate_calls += 1
        if duplicate_calls == 2:
            raise KeyboardInterrupt("rollback acquisition interrupted")
        return real_dup(descriptor)

    monkeypatch.setattr(
        staging_module.PublishedFileRollback,
        "_create",
        classmethod(observe_guard),
    )
    monkeypatch.setattr(staging_module.os, "dup", cancel_second_duplicate)

    with destination.stage_bytes(b"private report") as staged:
        staged.commit()
        with pytest.raises(
            KeyboardInterrupt,
            match="rollback acquisition interrupted",
        ):
            staged.retain_rollback()

    assert len(observed_rollbacks) == 1
    assert observed_rollbacks[0].closed
    assert path.read_bytes() == b"private report"
    destination.close()
    path.unlink()
