"""Descriptor-relative filesystem validation helpers."""

from __future__ import annotations

import os
import stat
from contextlib import suppress

from vexcalibur.execution_report_errors import BoundFileDestinationError


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
    with suppress(OSError):
        os.close(descriptor)


def _close_descriptor_retryable(descriptor: int) -> None:
    """Close an owned descriptor without losing retryable ownership."""
    try:
        expected = os.fstat(descriptor)
    except OSError:
        return
    try:
        os.close(descriptor)
    except BaseException:
        try:
            actual = os.fstat(descriptor)
        except OSError:
            return
        if not _same_identity(actual, expected):
            return
        raise
