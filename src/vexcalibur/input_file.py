"""Bounded local-file reads for untrusted document inputs."""

from __future__ import annotations

import os
import stat
from pathlib import Path

_READ_CHUNK_BYTES = 64 * 1024


class BoundedFileReadError(ValueError):
    """Raised when an input is not a readable, bounded regular file."""


def read_bounded_regular_file(
    path: Path,
    *,
    max_bytes: int,
    description: str,
) -> bytes:
    """Read at most ``max_bytes`` from one opened regular-file descriptor.

    Symbolic links are supported when their opened target is a regular file.
    FIFOs, devices, sockets, directories, and other non-regular targets are
    rejected after a nonblocking open and before any content is read.
    """
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        msg = f"Could not read {description}: {exc}"
        raise BoundedFileReadError(msg) from exc

    try:
        try:
            file_status = os.fstat(descriptor)
        except OSError as exc:
            msg = f"Could not inspect {description}: {exc}"
            raise BoundedFileReadError(msg) from exc

        if not stat.S_ISREG(file_status.st_mode):
            msg = f"{description} must resolve to a regular file"
            raise BoundedFileReadError(msg)
        if file_status.st_size > max_bytes:
            msg = f"{description} exceeds the {max_bytes} byte limit"
            raise BoundedFileReadError(msg)

        content = bytearray()
        remaining = max_bytes + 1
        while remaining:
            try:
                chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            except OSError as exc:
                msg = f"Could not read {description}: {exc}"
                raise BoundedFileReadError(msg) from exc
            if not chunk:
                break
            content.extend(chunk)
            remaining -= len(chunk)

        if len(content) > max_bytes:
            msg = f"{description} exceeds the {max_bytes} byte limit"
            raise BoundedFileReadError(msg)
        return bytes(content)
    finally:
        os.close(descriptor)
