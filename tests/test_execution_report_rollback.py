from __future__ import annotations

import os
import socket
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import vexcalibur.execution_report_destination as destination_module
import vexcalibur.execution_report_filesystem as filesystem_module
import vexcalibur.execution_report_staging as staging_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
    BoundFileDestinationError,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_retained_rollback_holds_inode_and_locks_identity_checked_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    rollback: staging_module.PublishedFileRollback

    with destination.stage_bytes(b"private report") as staged:
        rollback = staged._prepare_rollback()
        staged.commit()

    published = os.fstat(rollback.published_fd)
    assert published.st_dev == path.stat().st_dev
    assert published.st_ino == path.stat().st_ino
    lock_held = False
    real_remove = staging_module._remove_matching_destination

    @contextmanager
    def observe_lock(parent_fd: int) -> Iterator[None]:
        nonlocal lock_held
        assert parent_fd == rollback.parent_fd
        lock_held = True
        try:
            yield
        finally:
            lock_held = False

    def observe_remove(**kwargs: object) -> bool:
        assert lock_held
        expected = kwargs["expected"]
        assert isinstance(expected, os.stat_result)
        retained = os.fstat(rollback.published_fd)
        assert expected.st_dev == retained.st_dev
        assert expected.st_ino == retained.st_ino
        return real_remove(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        staging_module.lock_module,
        "_exclusive_destination_lock",
        observe_lock,
    )
    monkeypatch.setattr(
        staging_module,
        "_remove_matching_destination",
        observe_remove,
    )

    assert rollback.discard()
    assert not path.exists()
    rollback.close()
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_discarded_rollback_remains_idempotent_after_partial_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)

    with destination.stage_bytes(b"private report") as staged:
        rollback = staged._prepare_rollback()
        staged.commit()

    assert rollback.discard()
    parent_descriptor = rollback.parent_fd
    published_descriptor = rollback.published_fd
    real_dup2 = filesystem_module.os.dup2
    interrupted = False

    def interrupt_parent_transfer(
        source: int,
        candidate: int,
        *,
        inheritable: bool = True,
    ) -> int:
        nonlocal interrupted
        if candidate == parent_descriptor and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("parent close interrupted")
        return real_dup2(source, candidate, inheritable=inheritable)

    monkeypatch.setattr(
        filesystem_module.os,
        "dup2",
        interrupt_parent_transfer,
    )

    with pytest.raises(KeyboardInterrupt, match="parent close interrupted"):
        rollback.close()

    assert rollback.published_fd == -1
    assert rollback.parent_fd == -1
    assert rollback.discard()
    with pytest.raises(OSError):
        os.fstat(published_descriptor)
    os.fstat(parent_descriptor)

    rollback.close()
    assert rollback.closed
    os.fstat(parent_descriptor)
    os.close(parent_descriptor)
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_parent_swap_after_replace_rolls_back_through_bound_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "output"
    moved_parent = tmp_path / "moved-output"
    parent.mkdir()
    path = parent / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    real_verify_parent_path = BoundFileDestination.verify_parent_path
    swapped = False

    def swap_after_replace(bound: BoundFileDestination) -> None:
        nonlocal swapped
        if bound is destination and not swapped and path.exists():
            parent.rename(moved_parent)
            parent.mkdir()
            swapped = True
        real_verify_parent_path(bound)

    monkeypatch.setattr(
        BoundFileDestination,
        "verify_parent_path",
        swap_after_replace,
    )

    with pytest.raises(BoundFileDestinationError, match="parent directory changed"):
        destination.write_bytes(b"replacement")

    assert swapped
    assert not (moved_parent / path.name).exists()
    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_post_replace_failure_preserves_a_concurrent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    replacement = tmp_path / "replacement.json"
    destination = BoundFileDestination.prepare(path)
    real_fsync = destination_module.os.fsync
    calls = 0

    def fail_after_concurrent_replace(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            replacement.write_bytes(b"other writer")
            os.replace(replacement, path)
            raise OSError("directory fsync failed")
        real_fsync(descriptor)

    monkeypatch.setattr(
        destination_module.os,
        "fsync",
        fail_after_concurrent_replace,
    )

    with pytest.raises(BoundFileDestinationError, match="directory fsync failed"):
        destination.write_bytes(b"this writer")

    assert path.read_bytes() == b"other writer"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_stale_unlink_directory_fsync_failure_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    path.write_bytes(b"stale")

    def fail_fsync(descriptor: int) -> None:
        raise OSError("directory fsync failed")

    monkeypatch.setattr(destination_module.os, "fsync", fail_fsync)

    with pytest.raises(BoundFileDestinationError, match="could not remove stale"):
        BoundFileDestination.prepare(path, remove_existing=True)

    assert not path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_fifo_destination_is_rejected_without_removal(tmp_path: Path) -> None:
    path = tmp_path / "execution-report"
    os.mkfifo(path)

    with pytest.raises(BoundFileDestinationError, match="regular file"):
        BoundFileDestination.prepare(path, remove_existing=True)

    assert path.exists()
    assert stat.S_ISFIFO(path.lstat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_fifo_created_after_staging_is_not_replaced(tmp_path: Path) -> None:
    path = tmp_path / "execution-report"
    destination = BoundFileDestination.prepare(path)

    with destination.stage_bytes(b"report") as staged:
        os.mkfifo(path)
        with pytest.raises(BoundFileDestinationError, match="regular file"):
            staged.commit()

    destination.close()
    assert stat.S_ISFIFO(path.lstat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_unix_socket_destination_is_rejected_without_removal(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))

        with pytest.raises(BoundFileDestinationError, match="regular file"):
            BoundFileDestination.prepare(path, remove_existing=True)

        assert path.exists()
        assert stat.S_ISSOCK(path.lstat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_device_destination_is_rejected_without_replacement() -> None:
    path = Path("/dev/null")
    if not path.exists() or not stat.S_ISCHR(path.stat().st_mode):
        pytest.skip("/dev/null is not an available character device")

    with pytest.raises(BoundFileDestinationError, match="regular file"):
        BoundFileDestination.prepare(path)

    assert stat.S_ISCHR(path.stat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_normalized_filename_and_hardlink_aliases_are_rejected(tmp_path: Path) -> None:
    protected = tmp_path / "SBOM-\N{LATIN SMALL LETTER E WITH ACUTE}.json"
    protected.write_text("{}\n", encoding="utf-8")

    with pytest.raises(BoundFileDestinationError, match="must not replace"):
        BoundFileDestination.prepare(
            tmp_path / "sbom-e\N{COMBINING ACUTE ACCENT}.json",
            protected_paths=(protected,),
            remove_existing=True,
        )

    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(protected)
    with pytest.raises(BoundFileDestinationError, match="must not replace"):
        BoundFileDestination.prepare(
            hardlink,
            protected_paths=(protected,),
            remove_existing=True,
        )

    assert protected.read_text(encoding="utf-8") == "{}\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_open_regular_file_descriptor_alias_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "redirected-stdout.json"
    path.write_bytes(b"stdout")
    descriptor = os.open(path, os.O_WRONLY)
    try:
        with pytest.raises(BoundFileDestinationError, match="standard output"):
            BoundFileDestination.prepare(
                path,
                protected_descriptors=((descriptor, "standard output"),),
                remove_existing=True,
            )
    finally:
        os.close(descriptor)

    assert path.read_bytes() == b"stdout"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_open_fifo_descriptor_alias_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "redirected-stdout"
    os.mkfifo(path)
    descriptor = os.open(path, os.O_RDWR | os.O_NONBLOCK)
    try:
        with pytest.raises(BoundFileDestinationError, match="standard output"):
            BoundFileDestination.prepare(
                path,
                protected_descriptors=((descriptor, "standard output"),),
                remove_existing=True,
            )
    finally:
        os.close(descriptor)

    assert path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_maximum_length_destination_uses_bounded_temporary_name(tmp_path: Path) -> None:
    name_max = os.pathconf(tmp_path, "PC_NAME_MAX")
    if name_max < 64:
        pytest.skip("filesystem filename limit is too small for the staging contract")
    path = tmp_path / ("r" * name_max)

    BoundFileDestination.prepare(path).write_bytes(b"report")

    assert path.read_bytes() == b"report"
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


def test_windows_report_requests_fail_before_touching_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "execution-report.json"
    path.write_text('{"stale":true}\n', encoding="utf-8")
    monkeypatch.setattr(destination_module.os, "name", "nt")

    with pytest.raises(BoundFileDestinationError, match="not supported on Windows"):
        BoundFileDestination.prepare(path, remove_existing=True)

    assert path.read_text(encoding="utf-8") == '{"stale":true}\n'


@pytest.mark.skipif(os.name != "nt", reason="native Windows contract")
def test_native_windows_report_request_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "execution-report.json"
    path.write_text('{"stale":true}\n', encoding="utf-8")

    with pytest.raises(BoundFileDestinationError, match="not supported on Windows"):
        BoundFileDestination.prepare(path, remove_existing=True)

    assert path.read_text(encoding="utf-8") == '{"stale":true}\n'


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_bound_destinations_detect_same_normalized_name(tmp_path: Path) -> None:
    report = BoundFileDestination.prepare(tmp_path / "VEX.json")
    output = BoundFileDestination.prepare(tmp_path / "vex.json")

    assert report.aliases(output)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_swapped_output_parent_cannot_bypass_alias_check(tmp_path: Path) -> None:
    report_parent = tmp_path / "report-parent"
    report_parent.mkdir()
    output_parent = tmp_path / "output-parent"
    output_parent.mkdir()
    moved_output_parent = tmp_path / "moved-output-parent"
    report = BoundFileDestination.prepare(report_parent / "vex.json")

    output_parent.rename(moved_output_parent)
    output_parent.symlink_to(report_parent, target_is_directory=True)
    output = BoundFileDestination.prepare(output_parent / "vex.json")

    assert report.aliases(output)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_close_failure_does_not_escape_destination_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    real_close = destination_module.os.close

    def close_then_fail(descriptor: int) -> None:
        real_close(descriptor)
        raise OSError("close failed")

    monkeypatch.setattr(destination_module.os, "close", close_then_fail)

    destination.verify_parent_path()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_close_disowns_ambiguous_descriptor_before_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    descriptor = destination._parent_descriptor
    real_dup2 = filesystem_module.os.dup2
    interrupted = False

    def interrupt_before_transfer(
        source: int,
        candidate: int,
        *,
        inheritable: bool = True,
    ) -> int:
        nonlocal interrupted
        if candidate == descriptor and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("descriptor close interrupted")
        return real_dup2(source, candidate, inheritable=inheritable)

    monkeypatch.setattr(filesystem_module.os, "dup2", interrupt_before_transfer)

    with pytest.raises(KeyboardInterrupt, match="descriptor close interrupted"):
        destination.close()

    assert destination.closed
    assert destination._parent_descriptor == -1
    os.fstat(descriptor)
    destination.close()
    os.fstat(descriptor)
    os.close(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_close_completes_when_interrupted_after_physical_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    descriptor = destination._parent_descriptor
    real_dup2 = filesystem_module.os.dup2

    def interrupt_after_transfer(
        source: int,
        candidate: int,
        *,
        inheritable: bool = True,
    ) -> int:
        result = real_dup2(source, candidate, inheritable=inheritable)
        if candidate == descriptor:
            raise KeyboardInterrupt("descriptor was already closed")
        return result

    monkeypatch.setattr(filesystem_module.os, "dup2", interrupt_after_transfer)

    destination.close()

    assert destination.closed
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_staged_close_disowns_ambiguous_descriptor_before_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    scope = destination.stage_bytes(b"private report")
    staged = scope.__enter__()
    temporary_descriptor = staged.temporary_fd
    parent_descriptor = staged.parent_fd
    real_dup2 = filesystem_module.os.dup2
    interrupted = False

    def interrupt_parent_transfer(
        source: int,
        candidate: int,
        *,
        inheritable: bool = True,
    ) -> int:
        nonlocal interrupted
        if candidate == parent_descriptor and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("parent close interrupted")
        return real_dup2(source, candidate, inheritable=inheritable)

    monkeypatch.setattr(filesystem_module.os, "dup2", interrupt_parent_transfer)

    with pytest.raises(KeyboardInterrupt, match="parent close interrupted"):
        staged.close()

    assert staged.temporary_fd == -1
    assert staged.parent_fd == -1
    assert not staged.closed
    with pytest.raises(OSError):
        os.fstat(temporary_descriptor)
    os.fstat(parent_descriptor)

    scope.__exit__(None, None, None)
    assert staged.closed
    assert staged.parent_fd == -1
    os.fstat(parent_descriptor)
    os.close(parent_descriptor)
    destination.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_nul_destination_path_is_a_controlled_error(tmp_path: Path) -> None:
    path = Path(f"{tmp_path}/execution\0report.json")

    with pytest.raises(BoundFileDestinationError, match="NUL byte"):
        BoundFileDestination.prepare(path)
