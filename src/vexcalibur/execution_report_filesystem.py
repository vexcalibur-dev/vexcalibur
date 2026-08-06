"""Descriptor-relative filesystem validation helpers."""

from __future__ import annotations

import errno
import os
import signal
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass

from vexcalibur.execution_report_errors import BoundFileDestinationError


@contextmanager
def _defer_keyboard_interrupt() -> Iterator[None]:
    """Defer SIGINT until a returned descriptor has a recorded owner."""
    if os.name == "nt" or not hasattr(signal, "pthread_sigmask"):
        yield
        return
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _require_replaceable_leaf(metadata: os.stat_result) -> None:
    if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return
    raise BoundFileDestinationError(
        "destination must be absent, a regular file, or a symbolic link"
    )


def _require_private_regular_file(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise BoundFileDestinationError("staged file is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise BoundFileDestinationError("staged file mode changed before publication")


def _require_path_identity(
    *,
    parent_fd: int,
    name: str | bytes,
    expected: os.stat_result,
    role: str,
) -> None:
    try:
        actual = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise BoundFileDestinationError(f"{role} changed before publication") from exc
    if not _same_identity(actual, expected):
        raise BoundFileDestinationError(f"{role} changed before publication")
    if stat.S_IFMT(actual.st_mode) != stat.S_IFMT(expected.st_mode) or stat.S_IMODE(
        actual.st_mode
    ) != stat.S_IMODE(expected.st_mode):
        raise BoundFileDestinationError(f"{role} changed before publication")


def _remove_matching_destination(
    *,
    parent_fd: int,
    name: str | bytes,
    expected: os.stat_result,
) -> bool:
    try:
        actual = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not _same_identity(actual, expected):
        return True
    try:
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError:
        return False
    return True


def _close_descriptor(descriptor: int) -> None:
    outcome = _close_descriptor_retryable(descriptor)
    if outcome.unchanged:
        os.close(descriptor)
        if outcome.failure is not None and not isinstance(outcome.failure, Exception):
            raise outcome.failure
        return
    if outcome.failure is not None:
        raise outcome.failure
    if not outcome.released:
        raise RuntimeError("descriptor release returned no final state")


@dataclass(frozen=True, slots=True)
class _DescriptorCloseOutcome:
    released: bool
    unchanged: bool
    failure: BaseException | None


def _close_descriptor_retryable(descriptor: int) -> _DescriptorCloseOutcome:
    """Release a disowned descriptor without retrying its numeric value.

    Callers that retain ownership state must clear that state before calling.
    The outcome distinguishes a descriptor that is certainly unchanged from
    one whose state is ambiguous after an interrupted operation.
    """
    try:
        os.fstat(descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            return _DescriptorCloseOutcome(
                released=False,
                unchanged=True,
                failure=exc,
            )
        return _DescriptorCloseOutcome(
            released=True,
            unchanged=False,
            failure=None,
        )
    except BaseException as exc:
        return _DescriptorCloseOutcome(
            released=False,
            unchanged=True,
            failure=exc,
        )

    pipe_reader = -1
    pipe_writer = -1
    released = False
    failure: BaseException | None = None
    try:
        try:
            with _defer_keyboard_interrupt():
                pipe_reader, pipe_writer = os.pipe()
        except BaseException as exc:
            return _DescriptorCloseOutcome(
                released=False,
                unchanged=True,
                failure=exc,
            )
        os.dup2(pipe_reader, descriptor, inheritable=False)
        released = True
    except BaseException as exc:
        failure = exc
        try:
            descriptor_stat = os.fstat(descriptor)
            pipe_stat = os.fstat(pipe_reader)
        except OSError as probe_error:
            if probe_error.errno != errno.EBADF:
                failure = probe_error
        except BaseException as probe_error:
            failure = probe_error
        else:
            released = _same_identity(descriptor_stat, pipe_stat)
    finally:
        with suppress(BaseException):
            os.close(pipe_writer)
        with suppress(BaseException):
            os.close(pipe_reader)
        if released:
            with suppress(BaseException):
                os.close(descriptor)

    if failure is not None and not released:
        return _DescriptorCloseOutcome(
            released=False,
            unchanged=False,
            failure=failure,
        )
    return _DescriptorCloseOutcome(
        released=True,
        unchanged=False,
        failure=None,
    )
