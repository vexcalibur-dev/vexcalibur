from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

import vexcalibur.execution_report_locks as lock_module
from vexcalibur.execution_report_destination import (
    BoundFileDestination,
    BoundFileDestinationError,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_publication_waits_for_the_destination_lock(tmp_path: Path) -> None:
    import fcntl

    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    blocker = lock_module._open_private_destination_lock(
        destination._parent_descriptor,
    )
    attempted = threading.Event()
    completed = threading.Event()
    errors: list[BaseException] = []
    real_flock = fcntl.flock

    def observed_flock(descriptor: int, operation: int) -> None:
        if operation & fcntl.LOCK_EX and descriptor != blocker:
            attempted.set()
        real_flock(descriptor, operation)

    def publish() -> None:
        try:
            destination.write_bytes(b"report")
        except BaseException as exc:
            errors.append(exc)
        finally:
            completed.set()

    real_flock(blocker, fcntl.LOCK_EX)
    thread = threading.Thread(target=publish)
    try:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(fcntl, "flock", observed_flock)
            thread.start()
            assert attempted.wait(timeout=5)
            assert not completed.wait(timeout=0.05)
            assert not path.exists()
            real_flock(blocker, fcntl.LOCK_UN)
            thread.join(timeout=5)
    finally:
        real_flock(blocker, fcntl.LOCK_UN)
        os.close(blocker)
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert path.read_bytes() == b"report"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_publication_times_out_while_destination_is_locked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl

    path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(path)
    blocker = lock_module._open_private_destination_lock(
        destination._parent_descriptor,
    )
    monkeypatch.setattr(lock_module, "DESTINATION_LOCK_TIMEOUT_SECONDS", 0.0)

    fcntl.flock(blocker, fcntl.LOCK_EX)
    try:
        with pytest.raises(BoundFileDestinationError, match="timed out waiting"):
            destination.write_bytes(b"report")
    finally:
        fcntl.flock(blocker, fcntl.LOCK_UN)
        os.close(blocker)

    assert not path.exists()
    assert list(tmp_path.glob(".vexcalibur-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_parent_directory_flock_does_not_block_destination_lock(
    tmp_path: Path,
) -> None:
    import fcntl

    path = tmp_path / "report.json"
    blocker = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    fcntl.flock(blocker, fcntl.LOCK_EX)
    try:
        BoundFileDestination.prepare(path).write_bytes(b"report")
    finally:
        fcntl.flock(blocker, fcntl.LOCK_UN)
        os.close(blocker)

    assert path.read_bytes() == b"report"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destinations_in_one_directory_share_the_coordination_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl

    first = BoundFileDestination.prepare(tmp_path / "first-report.json")
    blocker = lock_module._open_private_destination_lock(
        first._parent_descriptor,
    )
    monkeypatch.setattr(lock_module, "DESTINATION_LOCK_TIMEOUT_SECONDS", 0.0)
    fcntl.flock(blocker, fcntl.LOCK_EX)
    try:
        with pytest.raises(BoundFileDestinationError, match="timed out waiting"):
            BoundFileDestination.prepare(tmp_path / "second-report.json").write_bytes(b"other")
    finally:
        fcntl.flock(blocker, fcntl.LOCK_UN)
        os.close(blocker)
        first.close()

    assert not (tmp_path / "second-report.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_lock_storage_is_private_and_bounded(tmp_path: Path) -> None:
    destination = BoundFileDestination.prepare(tmp_path / "report.json")
    for _ in range(512):
        descriptor = lock_module._open_private_destination_lock(
            destination._parent_descriptor,
        )
        os.close(descriptor)
    destination.close()

    lock_directory = tmp_path / lock_module.LOCK_DIRECTORY_NAME
    assert stat.S_IMODE(lock_directory.stat().st_mode) == 0o700
    lock_files = list(lock_directory.iterdir())
    assert [path.name for path in lock_files] == [lock_module.LOCK_FILE_NAME]
    assert stat.S_IMODE(lock_files[0].stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_coordination_directory_name_is_reserved(tmp_path: Path) -> None:
    with pytest.raises(BoundFileDestinationError, match=r"filename.*reserved"):
        BoundFileDestination.prepare(tmp_path / lock_module.LOCK_DIRECTORY_NAME)


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_symlinked_coordination_directory_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "lock-target"
    target.mkdir()
    (tmp_path / lock_module.LOCK_DIRECTORY_NAME).symlink_to(
        target,
        target_is_directory=True,
    )
    destination = BoundFileDestination.prepare(tmp_path / "report.json")

    with pytest.raises(BoundFileDestinationError, match="could not open"):
        destination.write_bytes(b"report")


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_destination_lock_creates_only_private_coordination_storage(tmp_path: Path) -> None:
    BoundFileDestination.prepare(tmp_path / "report.json").write_bytes(b"report")

    assert sorted(path.name for path in tmp_path.iterdir()) == [
        lock_module.LOCK_DIRECTORY_NAME,
        "report.json",
    ]


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_precreated_destination_lock_link_is_rejected(
    link_kind: str,
    tmp_path: Path,
) -> None:
    destination_path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(destination_path)
    lock_directory = tmp_path / lock_module.LOCK_DIRECTORY_NAME
    lock_directory.mkdir(mode=0o700)
    target = tmp_path / "lock-target"
    target.write_bytes(b"unchanged")
    target.chmod(0o600)
    lock_path = lock_directory / lock_module.LOCK_FILE_NAME
    if link_kind == "symlink":
        lock_path.symlink_to(target)
    else:
        lock_path.hardlink_to(target)

    with pytest.raises(BoundFileDestinationError, match="could not open"):
        destination.write_bytes(b"report")

    assert not destination_path.exists()
    assert target.read_bytes() == b"unchanged"


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
@pytest.mark.parametrize("mutation", ("type", "owner", "link-count"))
def test_destination_lock_metadata_guards_reject_mutation(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(destination_path)
    lock_descriptors: set[int] = set()
    real_open = lock_module.os.open
    real_fstat = lock_module.os.fstat

    def observe_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if isinstance(path, str) and path.endswith(".lock"):
            lock_descriptors.add(descriptor)
        return descriptor

    def mutate_lock_metadata(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if descriptor not in lock_descriptors:
            return metadata
        values = list(metadata)
        if mutation == "type":
            values[0] = stat.S_IFIFO | 0o600
        elif mutation == "owner":
            values[4] = metadata.st_uid + 1
        else:
            values[3] = 2
        return os.stat_result(values)

    monkeypatch.setattr(lock_module.os, "open", observe_open)
    monkeypatch.setattr(lock_module.os, "fstat", mutate_lock_metadata)

    with pytest.raises(BoundFileDestinationError, match="could not open"):
        destination.write_bytes(b"report")

    assert not destination_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX destination contract")
def test_replaced_lock_directory_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_path = tmp_path / "execution-report.json"
    destination = BoundFileDestination.prepare(destination_path)
    lock_directory = tmp_path / lock_module.LOCK_DIRECTORY_NAME
    moved_lock_directory = tmp_path / "moved-lock-directory"
    real_fchmod = lock_module.os.fchmod
    replaced = False

    def replace_after_open(descriptor: int, mode: int) -> None:
        nonlocal replaced
        real_fchmod(descriptor, mode)
        if mode == 0o700 and not replaced:
            replaced = True
            lock_directory.rename(moved_lock_directory)
            lock_directory.mkdir(mode=0o700)

    monkeypatch.setattr(lock_module.os, "fchmod", replace_after_open)

    with pytest.raises(BoundFileDestinationError, match="could not open"):
        destination.write_bytes(b"report")

    assert not destination_path.exists()
