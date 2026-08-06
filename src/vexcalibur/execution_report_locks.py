"""Coordination locks for descriptor-bound output destinations."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from typing import Protocol

from vexcalibur.execution_report_errors import (
    BoundFileDestinationError,
    DestinationLockError,
)
from vexcalibur.execution_report_filesystem import (
    _close_descriptor,
    _defer_keyboard_interrupt,
    _same_identity,
)

DESTINATION_LOCK_TIMEOUT_SECONDS = 10.0
DESTINATION_LOCK_RETRY_SECONDS = 0.05
LOCK_DIRECTORY_NAME = ".vexcalibur-locks"
LOCK_FILE_NAME = "directory.lock"


class _LockableDestination(Protocol):
    """The destination operations needed by lock coordination."""

    def _bound_parent_stat(self) -> os.stat_result: ...

    def _coordination_key(self) -> bytes: ...

    def _require_parent_descriptor(self) -> int: ...

    def aliases_descriptor(self, descriptor: int) -> bool: ...


@contextmanager
def acquire_destination_locks(
    destinations: tuple[_LockableDestination | None, ...],
) -> Iterator[None]:
    """Lock every distinct destination directory in deterministic order."""
    destinations_by_lock: dict[tuple[int, int], _LockableDestination] = {}
    for destination in destinations:
        if destination is None:
            continue
        try:
            metadata = destination._bound_parent_stat()
        except BoundFileDestinationError as exc:
            raise DestinationLockError(destination, exc) from exc
        destinations_by_lock.setdefault(
            (
                metadata.st_dev,
                metadata.st_ino,
            ),
            destination,
        )

    active_destinations = tuple(
        destination for destination in destinations if destination is not None
    )
    with ExitStack() as stack:
        lock_descriptors: list[int] = []
        for key in sorted(destinations_by_lock):
            destination = destinations_by_lock[key]
            try:
                lock_descriptors.append(
                    stack.enter_context(
                        _exclusive_destination_lock(
                            destination._require_parent_descriptor(),
                        )
                    )
                )
            except BoundFileDestinationError as exc:
                raise DestinationLockError(destination, exc) from exc
        for destination in active_destinations:
            if any(destination.aliases_descriptor(descriptor) for descriptor in lock_descriptors):
                cause = BoundFileDestinationError(
                    "destination must not replace a Vexcalibur coordination lock"
                )
                raise DestinationLockError(destination, cause)
        yield


@contextmanager
def acquire_stdout_sequence_lock(
    destination: _LockableDestination,
) -> Iterator[None]:
    """Serialize stdout and report publication for one report leaf."""
    lock_name = f"stdout-{hashlib.sha256(destination._coordination_key()).hexdigest()}.lock"
    try:
        with _exclusive_named_destination_lock(
            destination._require_parent_descriptor(),
            lock_name,
        ) as descriptor:
            if destination.aliases_descriptor(descriptor):
                raise BoundFileDestinationError(
                    "destination must not replace a Vexcalibur coordination lock"
                )
            yield
    except BoundFileDestinationError as exc:
        raise DestinationLockError(destination, exc) from exc


@contextmanager
def _exclusive_destination_lock(
    parent_descriptor: int,
) -> Iterator[int]:
    with _exclusive_named_destination_lock(
        parent_descriptor,
        LOCK_FILE_NAME,
    ) as descriptor:
        yield descriptor


@contextmanager
def _exclusive_named_destination_lock(
    parent_descriptor: int,
    lock_file_name: str,
) -> Iterator[int]:
    lock_descriptor = -1
    try:
        try:
            metadata = os.fstat(parent_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError("destination parent is not a directory")
            with _defer_keyboard_interrupt():
                lock_descriptor = (
                    _open_private_destination_lock(parent_descriptor)
                    if lock_file_name == LOCK_FILE_NAME
                    else _open_private_named_destination_lock(
                        parent_descriptor,
                        lock_file_name,
                    )
                )
        except (
            BoundFileDestinationError,
            NotImplementedError,
            OSError,
            ValueError,
        ) as exc:
            raise BoundFileDestinationError("could not open the destination lock") from exc
        with _exclusive_open_lock(lock_descriptor):
            yield lock_descriptor
    finally:
        _close_descriptor(lock_descriptor)


@contextmanager
def _exclusive_open_lock(lock_descriptor: int) -> Iterator[None]:
    """Exclusively lock one already-open private coordination file."""
    import fcntl

    try:
        metadata = os.fstat(lock_descriptor)
    except OSError as exc:
        raise BoundFileDestinationError("could not inspect the destination lock") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise BoundFileDestinationError("destination lock must be a private regular file")

    deadline = time.monotonic() + DESTINATION_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as exc:
            if not isinstance(exc, BlockingIOError) and exc.errno not in {
                errno.EACCES,
                errno.EAGAIN,
            }:
                raise BoundFileDestinationError("could not lock the destination") from exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundFileDestinationError(
                    "timed out waiting for the destination lock"
                ) from exc
            time.sleep(min(DESTINATION_LOCK_RETRY_SECONDS, remaining))
    try:
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)


def _open_private_destination_lock(
    parent_descriptor: int,
) -> int:
    return _open_private_named_destination_lock(
        parent_descriptor,
        LOCK_FILE_NAME,
    )


def _open_private_named_destination_lock(
    parent_descriptor: int,
    lock_file_name: str,
) -> int:
    lock_directory_descriptor = -1
    descriptor = -1
    try:
        with suppress(FileExistsError):
            os.mkdir(
                LOCK_DIRECTORY_NAME,
                mode=0o700,
                dir_fd=parent_descriptor,
            )
        initial_lock_directory_metadata = os.stat(
            LOCK_DIRECTORY_NAME,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(initial_lock_directory_metadata.st_mode)
            or initial_lock_directory_metadata.st_uid != os.getuid()
        ):
            raise OSError("lock directory must be owned by the current user")
        os.chmod(
            LOCK_DIRECTORY_NAME,
            0o700,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )

        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        with _defer_keyboard_interrupt():
            lock_directory_descriptor = os.open(
                LOCK_DIRECTORY_NAME,
                directory_flags,
                dir_fd=parent_descriptor,
            )
        lock_directory_metadata = os.fstat(lock_directory_descriptor)
        if (
            not stat.S_ISDIR(lock_directory_metadata.st_mode)
            or lock_directory_metadata.st_uid != os.getuid()
            or not _same_identity(
                lock_directory_metadata,
                initial_lock_directory_metadata,
            )
        ):
            raise OSError("lock directory must be owned by the current user")
        os.fchmod(lock_directory_descriptor, 0o700)
        _require_lock_directory_identity(
            parent_descriptor=parent_descriptor,
            expected=lock_directory_metadata,
        )

        lock_flags = os.O_RDWR | os.O_CREAT
        lock_flags |= getattr(os, "O_CLOEXEC", 0)
        lock_flags |= getattr(os, "O_NOFOLLOW", 0)
        with _defer_keyboard_interrupt():
            descriptor = os.open(
                lock_file_name,
                lock_flags,
                0o600,
                dir_fd=lock_directory_descriptor,
            )
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != os.getuid()
            or lock_metadata.st_nlink != 1
        ):
            raise OSError("destination lock must be a private regular file")
        os.fchmod(descriptor, 0o600)
        final_lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final_lock_metadata.st_mode)
            or final_lock_metadata.st_uid != os.getuid()
            or final_lock_metadata.st_nlink != 1
            or not _same_identity(final_lock_metadata, lock_metadata)
        ):
            raise OSError("destination lock must be a private regular file")
        _require_lock_directory_identity(
            parent_descriptor=parent_descriptor,
            expected=lock_directory_metadata,
        )
        return descriptor
    except BaseException:
        _close_descriptor(descriptor)
        raise
    finally:
        _close_descriptor(lock_directory_descriptor)


def _require_lock_directory_identity(
    *,
    parent_descriptor: int,
    expected: os.stat_result,
) -> None:
    actual = os.stat(
        LOCK_DIRECTORY_NAME,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if not stat.S_ISDIR(actual.st_mode) or not _same_identity(actual, expected):
        raise OSError("destination lock directory changed")
