"""Bound archive metadata before Python materializes archive members."""

from __future__ import annotations

import gzip
import math
import os
import stat
import struct
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_SIZE = 22
_ZIP_MAX_COMMENT_BYTES = 65_535
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_TAR_BLOCK_BYTES = 512
_TAR_PAX_TYPES = frozenset({b"X", b"g", b"x"})
_TAR_REJECTED_EXTENSION_TYPES = frozenset({b"K", b"L", b"S"})
_TAR_MAX_PAX_BYTES = 1024 * 1024
_TAR_MAX_PAX_RECORDS = 10_000
_TAR_ALLOWED_PAX_KEYS = frozenset({b"mtime"})
_DEFAULT_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


class ArchivePreflightError(ValueError):
    """Raised when an archive exceeds a pre-materialization boundary."""


def preflight_zip_member_count(
    path: Path,
    *,
    artifact: str,
    maximum_members: int,
    maximum_directory_bytes: int,
    maximum_archive_bytes: int = _DEFAULT_MAX_ARCHIVE_BYTES,
) -> bytes:
    """Return a preflighted snapshot before ``zipfile`` constructs members."""
    snapshot = _read_archive_snapshot(
        path,
        artifact=artifact,
        maximum_bytes=maximum_archive_bytes,
    )
    size = len(snapshot)
    tail_size = min(size, _ZIP_EOCD_SIZE + _ZIP_MAX_COMMENT_BYTES)
    stream = BytesIO(snapshot)
    stream.seek(size - tail_size)
    tail = stream.read(tail_size)

    search_end = len(tail)
    while True:
        offset = tail.rfind(_ZIP_EOCD_SIGNATURE, 0, search_end)
        if offset < 0:
            raise ArchivePreflightError(f"{artifact} has no bounded ZIP directory record")
        if offset + _ZIP_EOCD_SIZE <= len(tail):
            (
                _signature,
                disk_number,
                directory_disk,
                disk_members,
                total_members,
                directory_size,
                directory_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2LH", tail, offset)
            if offset + _ZIP_EOCD_SIZE + comment_size == len(tail):
                break
        search_end = offset

    if disk_number != 0 or directory_disk != 0 or disk_members != total_members:
        raise ArchivePreflightError(f"{artifact} uses an unsupported multidisk ZIP")
    if total_members == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF:
        raise ArchivePreflightError(f"{artifact} uses unsupported ZIP64 metadata")
    if total_members > maximum_members:
        raise ArchivePreflightError(f"{artifact} contains too many archive members")
    if directory_size > maximum_directory_bytes:
        raise ArchivePreflightError(f"{artifact} ZIP central directory exceeds the byte limit")
    directory_end = directory_offset + directory_size
    eocd_offset = size - tail_size + offset
    if directory_end != eocd_offset:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP directory boundary")
    _preflight_zip_central_directory(
        stream,
        artifact=artifact,
        directory_offset=directory_offset,
        directory_size=directory_size,
        expected_members=total_members,
        maximum_members=maximum_members,
    )
    return snapshot


def _preflight_zip_central_directory(
    stream: BinaryIO,
    *,
    artifact: str,
    directory_offset: int,
    directory_size: int,
    expected_members: int,
    maximum_members: int,
) -> None:
    consumed = 0
    members = 0
    stream.seek(directory_offset)
    while consumed < directory_size:
        header = stream.read(_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE)
        if len(header) != _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
            raise ArchivePreflightError(f"{artifact} has a truncated ZIP central directory")
        if header[:4] != _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
            raise ArchivePreflightError(f"{artifact} has an invalid ZIP central directory")
        filename_size, extra_size, comment_size = struct.unpack_from(
            "<3H",
            header,
            28,
        )
        variable_size = filename_size + extra_size + comment_size
        consumed += _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + variable_size
        if consumed > directory_size:
            raise ArchivePreflightError(f"{artifact} has an invalid ZIP central directory boundary")
        members += 1
        if members > maximum_members:
            raise ArchivePreflightError(f"{artifact} contains too many archive members")
        stream.seek(variable_size, 1)
    if consumed != directory_size or members != expected_members:
        raise ArchivePreflightError(f"{artifact} has inconsistent ZIP central directory metadata")


def preflight_tar_gzip_stream(
    path: Path,
    *,
    artifact: str,
    maximum_members: int,
    maximum_file_bytes: int,
    maximum_archive_bytes: int = _DEFAULT_MAX_ARCHIVE_BYTES,
) -> bytes:
    """Return a bounded gzip-compressed tar snapshot for ``tarfile``.

    Setuptools emits one PAX ``mtime`` record for each sdist member. This
    preflight accepts that bounded timestamp metadata but rejects PAX keys that
    can replace paths, sizes, or link targets. GNU long-name, long-link, and
    sparse extensions are rejected for the same reason.
    """
    snapshot = _read_archive_snapshot(
        path,
        artifact=artifact,
        maximum_bytes=maximum_archive_bytes,
    )
    maximum_stream_bytes = (
        maximum_file_bytes
        + (maximum_members * ((_TAR_BLOCK_BYTES - 1) + _TAR_BLOCK_BYTES))
        + _TAR_MAX_PAX_BYTES
        + ((maximum_members + 1) * ((_TAR_BLOCK_BYTES - 1) + _TAR_BLOCK_BYTES))
        + (2 * _TAR_BLOCK_BYTES)
    )
    consumed = 0
    file_bytes = 0
    members = 0
    pax_bytes = 0
    pax_headers = 0
    try:
        with BytesIO(snapshot) as raw, gzip.GzipFile(fileobj=raw, mode="rb") as stream:
            while True:
                header, consumed = _read_bounded(
                    stream,
                    _TAR_BLOCK_BYTES,
                    consumed=consumed,
                    maximum=maximum_stream_bytes,
                    artifact=artifact,
                )
                if not header:
                    return snapshot
                if len(header) != _TAR_BLOCK_BYTES:
                    raise ArchivePreflightError(f"{artifact} has a truncated tar header")
                if not any(header):
                    continue

                member_type = header[156:157]
                if member_type in _TAR_REJECTED_EXTENSION_TYPES:
                    raise ArchivePreflightError(
                        f"{artifact} contains an unsupported tar extension header"
                    )
                member_size = _parse_tar_size(header[124:136], artifact=artifact)
                if member_type in _TAR_PAX_TYPES:
                    pax_headers += 1
                    if pax_headers > maximum_members + 1:
                        raise ArchivePreflightError(
                            f"{artifact} contains too many PAX metadata headers"
                        )
                    pax_bytes += member_size
                    if pax_bytes > _TAR_MAX_PAX_BYTES:
                        raise ArchivePreflightError(
                            f"{artifact} PAX metadata exceeds the byte limit"
                        )
                    padded_size = _padded_tar_size(member_size)
                    previous_consumed = consumed
                    payload, consumed = _read_bounded(
                        stream,
                        padded_size,
                        consumed=consumed,
                        maximum=maximum_stream_bytes,
                        artifact=artifact,
                    )
                    if consumed - previous_consumed != padded_size:
                        raise ArchivePreflightError(
                            f"{artifact} has a truncated PAX metadata record"
                        )
                    _validate_pax_payload(payload[:member_size], artifact=artifact)
                    continue

                members += 1
                if members > maximum_members:
                    raise ArchivePreflightError(f"{artifact} contains too many archive members")
                file_bytes += member_size
                if file_bytes > maximum_file_bytes:
                    raise ArchivePreflightError(
                        f"{artifact} exceeds the cumulative uncompressed byte limit"
                    )
                padded_size = _padded_tar_size(member_size)
                previous_consumed = consumed
                _, consumed = _read_bounded(
                    stream,
                    padded_size,
                    consumed=consumed,
                    maximum=maximum_stream_bytes,
                    artifact=artifact,
                    retain=False,
                )
                if consumed - previous_consumed != padded_size:
                    raise ArchivePreflightError(f"{artifact} has a truncated tar member")
    except (gzip.BadGzipFile, OSError, EOFError) as exc:
        raise ArchivePreflightError(f"{artifact} compressed tar stream is invalid") from exc


def _read_archive_snapshot(
    path: Path,
    *,
    artifact: str,
    maximum_bytes: int,
) -> bytes:
    """Return bounded bytes from one unchanged regular-file identity."""
    descriptor = -1
    try:
        before_open = path.lstat()
        if not stat.S_ISREG(before_open.st_mode):
            raise ArchivePreflightError(f"{artifact} must be a regular, non-symlink file")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before_open, opened):
            raise ArchivePreflightError(f"{artifact} changed while it was opened")
        if opened.st_size > maximum_bytes:
            raise ArchivePreflightError(f"{artifact} exceeds the compressed byte limit")

        content = bytearray()
        while len(content) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after_read = os.fstat(descriptor)
        current_path = path.lstat()
    except ArchivePreflightError:
        raise
    except OSError as exc:
        raise ArchivePreflightError(f"{artifact} could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(content) > maximum_bytes:
        raise ArchivePreflightError(f"{artifact} exceeds the compressed byte limit")
    snapshots = (after_read, current_path)
    if any(not stat.S_ISREG(snapshot.st_mode) for snapshot in snapshots):
        raise ArchivePreflightError(f"{artifact} changed while it was read")
    if any(not os.path.samestat(opened, snapshot) for snapshot in snapshots):
        raise ArchivePreflightError(f"{artifact} changed while it was read")
    expected_state = (
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    if (
        any(
            (
                snapshot.st_size,
                snapshot.st_mtime_ns,
                snapshot.st_ctime_ns,
            )
            != expected_state
            for snapshot in snapshots
        )
        or len(content) != opened.st_size
    ):
        raise ArchivePreflightError(f"{artifact} changed while it was read")
    return bytes(content)


def _padded_tar_size(size: int) -> int:
    return ((size + _TAR_BLOCK_BYTES - 1) // _TAR_BLOCK_BYTES) * _TAR_BLOCK_BYTES


def _validate_pax_payload(payload: bytes, *, artifact: str) -> None:
    offset = 0
    records = 0
    while offset < len(payload):
        separator = payload.find(b" ", offset, min(len(payload), offset + 32))
        if separator < 0:
            raise ArchivePreflightError(f"{artifact} has invalid PAX metadata")
        raw_length = payload[offset:separator]
        if (
            not raw_length
            or not raw_length.isdigit()
            or (len(raw_length) > 1 and raw_length.startswith(b"0"))
        ):
            raise ArchivePreflightError(f"{artifact} has invalid PAX metadata")
        record_end = offset + int(raw_length)
        if record_end <= separator + 2 or record_end > len(payload):
            raise ArchivePreflightError(f"{artifact} has invalid PAX metadata")
        record = payload[separator + 1 : record_end]
        if not record.endswith(b"\n") or b"=" not in record:
            raise ArchivePreflightError(f"{artifact} has invalid PAX metadata")
        key, value = record[:-1].split(b"=", 1)
        if key not in _TAR_ALLOWED_PAX_KEYS:
            raise ArchivePreflightError(f"{artifact} contains an unsupported PAX metadata key")
        try:
            value.decode("utf-8")
            timestamp = float(value)
        except (UnicodeDecodeError, ValueError):
            raise ArchivePreflightError(f"{artifact} has invalid PAX metadata") from None
        if not math.isfinite(timestamp):
            raise ArchivePreflightError(f"{artifact} has invalid PAX metadata")
        records += 1
        if records > _TAR_MAX_PAX_RECORDS:
            raise ArchivePreflightError(f"{artifact} contains too many PAX metadata records")
        offset = record_end


def _read_bounded(
    stream: gzip.GzipFile,
    size: int,
    *,
    consumed: int,
    maximum: int,
    artifact: str,
    retain: bool = True,
) -> tuple[bytes, int]:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            break
        consumed += len(chunk)
        if consumed > maximum:
            raise ArchivePreflightError(
                f"{artifact} exceeds the cumulative uncompressed byte limit"
            )
        if retain:
            chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), consumed


def _parse_tar_size(field: bytes, *, artifact: str) -> int:
    if field[:1] and field[0] & 0x80:
        raise ArchivePreflightError(f"{artifact} uses an unsupported base-256 tar size")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value:
        return 0
    if any(character not in b"01234567" for character in value):
        raise ArchivePreflightError(f"{artifact} has an invalid tar member size")
    return int(value, 8)
