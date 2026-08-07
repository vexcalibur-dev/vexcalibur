"""Bound archive metadata before Python materializes archive members."""

from __future__ import annotations

import gzip
import math
import os
import stat
import struct
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_SIZE = 22
_ZIP_MAX_COMMENT_BYTES = 65_535
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_EOCD_MINIMUM_SIZE = 56
_ZIP64_EOCD_MINIMUM_BODY_SIZE = 44
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_LOCATOR_SIZE = 20
_ZIP64_MINIMUM_VERSION = 45
_ZIP64_EXTENSIBLE_DATA_HEADER_SIZE = 6
_ZIP64_MAX_EXTENSIBLE_DATA_BLOCKS = 10_000
_ZIP_MAX_EXTRA_FIELDS_PER_MEMBER = 10
_ZIP_UINT16_MAX = (1 << 16) - 1
_ZIP_UINT32_MAX = (1 << 32) - 1
_TAR_BLOCK_BYTES = 512
_TAR_PAX_TYPES = frozenset({b"X", b"g", b"x"})
_TAR_REJECTED_EXTENSION_TYPES = frozenset({b"K", b"L", b"S"})
_TAR_MAX_PAX_HEADERS = 10_001
_TAR_MAX_CONSECUTIVE_PAX_HEADERS = 8
_TAR_MAX_PAX_BYTES = 1024 * 1024
_TAR_MAX_PAX_RECORDS = 10_000
_TAR_ALLOWED_PAX_KEYS = frozenset({b"mtime"})
_DEFAULT_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


class ArchivePreflightError(ValueError):
    """Raised when an archive exceeds a pre-materialization boundary."""


class ArchiveSnapshot:
    """An unchanged, bounded archive image captured by one file descriptor."""

    __slots__ = ("_contents",)

    def __init__(self, contents: bytearray) -> None:
        self._contents = contents

    def __len__(self) -> int:
        return len(self._contents)

    def open(self) -> BytesIO:
        """Return an independent binary stream over the captured contents."""
        return BytesIO(self._contents)


@dataclass(frozen=True)
class _ZipDirectoryRecord:
    disk_number: int
    directory_disk: int
    disk_members: int
    total_members: int
    directory_size: int
    directory_offset: int
    directory_end_offset: int
    relative_directory_end_offset: int | None


@dataclass(frozen=True)
class _Zip64ExtensibleData:
    offset: int
    size: int


def preflight_zip_archive(
    path: Path,
    *,
    artifact: str,
    maximum_members: int,
    maximum_directory_bytes: int,
    maximum_archive_bytes: int = _DEFAULT_MAX_ARCHIVE_BYTES,
) -> ArchiveSnapshot:
    """Return a preflighted snapshot before ``zipfile`` constructs members."""
    snapshot = _read_archive_snapshot(
        path,
        artifact=artifact,
        maximum_bytes=maximum_archive_bytes,
    )
    size = len(snapshot)
    tail_size = min(size, _ZIP_EOCD_SIZE + _ZIP_MAX_COMMENT_BYTES)
    with snapshot.open() as stream:
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)

        offset = tail.rfind(_ZIP_EOCD_SIGNATURE)
        if offset < 0 or offset + _ZIP_EOCD_SIZE > len(tail):
            raise ArchivePreflightError(f"{artifact} has no bounded ZIP directory record")
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
        if offset + _ZIP_EOCD_SIZE + comment_size != len(tail):
            raise ArchivePreflightError(f"{artifact} has an invalid ZIP directory record")

        eocd_offset = size - tail_size + offset
        directory, extensible_data = _resolve_zip_directory_record(
            stream,
            artifact=artifact,
            classic=_ZipDirectoryRecord(
                disk_number=disk_number,
                directory_disk=directory_disk,
                disk_members=disk_members,
                total_members=total_members,
                directory_size=directory_size,
                directory_offset=directory_offset,
                directory_end_offset=eocd_offset,
                relative_directory_end_offset=None,
            ),
        )
        if (
            directory.disk_number != 0
            or directory.directory_disk != 0
            or directory.disk_members != directory.total_members
        ):
            raise ArchivePreflightError(f"{artifact} uses an unsupported multidisk ZIP")
        _enforce_zip_directory_limits(
            directory,
            artifact=artifact,
            maximum_members=maximum_members,
            maximum_directory_bytes=maximum_directory_bytes,
        )
        directory = _translate_zip_directory_offset(directory, artifact=artifact)
        if extensible_data is not None:
            stream.seek(extensible_data.offset)
            _preflight_zip64_extensible_data(
                stream,
                artifact=artifact,
                size=extensible_data.size,
            )
        _preflight_zip_central_directory(
            stream,
            artifact=artifact,
            directory_offset=directory.directory_offset,
            directory_size=directory.directory_size,
            expected_members=directory.total_members,
            maximum_members=maximum_members,
        )
    return snapshot


def _resolve_zip_directory_record(
    stream: BinaryIO,
    *,
    artifact: str,
    classic: _ZipDirectoryRecord,
) -> tuple[_ZipDirectoryRecord, _Zip64ExtensibleData | None]:
    locator_offset = classic.directory_end_offset - _ZIP64_LOCATOR_SIZE
    locator = b""
    if locator_offset >= 0:
        stream.seek(locator_offset)
        locator = stream.read(_ZIP64_LOCATOR_SIZE)
    if len(locator) != _ZIP64_LOCATOR_SIZE or not locator.startswith(_ZIP64_LOCATOR_SIGNATURE):
        return classic, None

    _signature, record_disk, record_offset, total_disks = struct.unpack("<4sLQL", locator)
    if record_disk != 0 or total_disks != 1:
        raise ArchivePreflightError(f"{artifact} uses an unsupported multidisk ZIP64 archive")
    if record_offset > locator_offset or locator_offset - record_offset < _ZIP64_EOCD_MINIMUM_SIZE:
        raise ArchivePreflightError(f"{artifact} has a truncated ZIP64 directory record")

    physical_record_offset = record_offset
    stream.seek(record_offset)
    if (
        stream.read(len(_ZIP64_EOCD_SIGNATURE)) != _ZIP64_EOCD_SIGNATURE
        and record_offset != locator_offset - _ZIP64_EOCD_MINIMUM_SIZE
    ):
        physical_record_offset = locator_offset - _ZIP64_EOCD_MINIMUM_SIZE

    return _read_zip64_directory_record(
        stream,
        artifact=artifact,
        classic=classic,
        record_offset=physical_record_offset,
        relative_record_offset=record_offset,
        locator_offset=locator_offset,
    )


def _read_zip64_directory_record(
    stream: BinaryIO,
    *,
    artifact: str,
    classic: _ZipDirectoryRecord,
    record_offset: int,
    relative_record_offset: int,
    locator_offset: int,
) -> tuple[_ZipDirectoryRecord, _Zip64ExtensibleData]:
    stream.seek(record_offset)
    record = stream.read(_ZIP64_EOCD_MINIMUM_SIZE)
    if len(record) != _ZIP64_EOCD_MINIMUM_SIZE:
        raise ArchivePreflightError(f"{artifact} has a truncated ZIP64 directory record")
    (
        signature,
        record_size,
        _version_made_by,
        version_needed,
        disk_number,
        directory_disk,
        disk_members,
        total_members,
        directory_size,
        directory_offset,
    ) = struct.unpack("<4sQ2H2L4Q", record)
    if signature != _ZIP64_EOCD_SIGNATURE:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP64 directory record")
    if record_size < _ZIP64_EOCD_MINIMUM_BODY_SIZE:
        raise ArchivePreflightError(f"{artifact} has a truncated ZIP64 directory record")
    if record_offset + 12 + record_size != locator_offset:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP64 directory record boundary")
    if version_needed < _ZIP64_MINIMUM_VERSION:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP64 version")

    zip64 = _ZipDirectoryRecord(
        disk_number=disk_number,
        directory_disk=directory_disk,
        disk_members=disk_members,
        total_members=total_members,
        directory_size=directory_size,
        directory_offset=directory_offset,
        directory_end_offset=record_offset,
        relative_directory_end_offset=relative_record_offset,
    )
    _validate_classic_zip64_consistency(classic, zip64, artifact=artifact)
    return (
        zip64,
        _Zip64ExtensibleData(
            offset=record_offset + _ZIP64_EOCD_MINIMUM_SIZE,
            size=record_size - _ZIP64_EOCD_MINIMUM_BODY_SIZE,
        ),
    )


def _translate_zip_directory_offset(
    directory: _ZipDirectoryRecord,
    *,
    artifact: str,
) -> _ZipDirectoryRecord:
    relative_end = directory.directory_offset + directory.directory_size
    expected_relative_end = directory.relative_directory_end_offset
    if expected_relative_end is not None and relative_end != expected_relative_end:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP directory boundary")
    prefix_size = directory.directory_end_offset - (
        relative_end if expected_relative_end is None else expected_relative_end
    )
    if prefix_size < 0:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP directory boundary")
    return _ZipDirectoryRecord(
        disk_number=directory.disk_number,
        directory_disk=directory.directory_disk,
        disk_members=directory.disk_members,
        total_members=directory.total_members,
        directory_size=directory.directory_size,
        directory_offset=directory.directory_offset + prefix_size,
        directory_end_offset=directory.directory_end_offset,
        relative_directory_end_offset=directory.relative_directory_end_offset,
    )


def _enforce_zip_directory_limits(
    directory: _ZipDirectoryRecord,
    *,
    artifact: str,
    maximum_members: int,
    maximum_directory_bytes: int,
) -> None:
    if directory.total_members > maximum_members:
        raise ArchivePreflightError(f"{artifact} contains too many archive members")
    if directory.directory_size > maximum_directory_bytes:
        raise ArchivePreflightError(f"{artifact} ZIP central directory exceeds the byte limit")


def _preflight_zip64_extensible_data(
    stream: BinaryIO,
    *,
    artifact: str,
    size: int,
) -> None:
    remaining = size
    blocks = 0
    while remaining:
        blocks += 1
        if blocks > _ZIP64_MAX_EXTENSIBLE_DATA_BLOCKS:
            raise ArchivePreflightError(
                f"{artifact} contains too many ZIP64 extensible data blocks"
            )
        if remaining < _ZIP64_EXTENSIBLE_DATA_HEADER_SIZE:
            raise ArchivePreflightError(f"{artifact} has invalid ZIP64 extensible data")
        header = stream.read(_ZIP64_EXTENSIBLE_DATA_HEADER_SIZE)
        if len(header) != _ZIP64_EXTENSIBLE_DATA_HEADER_SIZE:
            raise ArchivePreflightError(f"{artifact} has truncated ZIP64 extensible data")
        _header_id, data_size = struct.unpack("<HL", header)
        remaining -= _ZIP64_EXTENSIBLE_DATA_HEADER_SIZE
        if data_size > remaining:
            raise ArchivePreflightError(f"{artifact} has invalid ZIP64 extensible data")
        stream.seek(data_size, os.SEEK_CUR)
        remaining -= data_size


def _validate_classic_zip64_consistency(
    classic: _ZipDirectoryRecord,
    zip64: _ZipDirectoryRecord,
    *,
    artifact: str,
) -> None:
    comparisons = (
        (classic.disk_number, zip64.disk_number, _ZIP_UINT16_MAX),
        (classic.directory_disk, zip64.directory_disk, _ZIP_UINT16_MAX),
        (classic.disk_members, zip64.disk_members, _ZIP_UINT16_MAX),
        (classic.total_members, zip64.total_members, _ZIP_UINT16_MAX),
        (classic.directory_size, zip64.directory_size, _ZIP_UINT32_MAX),
        (classic.directory_offset, zip64.directory_offset, _ZIP_UINT32_MAX),
    )
    if any(
        classic_value != sentinel and classic_value != zip64_value
        for classic_value, zip64_value, sentinel in comparisons
    ):
        raise ArchivePreflightError(
            f"{artifact} has contradictory ZIP and ZIP64 directory metadata"
        )


def _preflight_zip_central_directory(
    stream: BinaryIO,
    *,
    artifact: str,
    directory_offset: int,
    directory_size: int,
    expected_members: int,
    maximum_members: int,
) -> None:
    if expected_members * _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE > directory_size:
        raise ArchivePreflightError(f"{artifact} has a truncated ZIP central directory")
    consumed = 0
    members = 0
    extra_fields = 0
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
        variable_data = stream.read(variable_size)
        if len(variable_data) != variable_size:
            raise ArchivePreflightError(f"{artifact} has a truncated ZIP central directory")
        extra = variable_data[filename_size : filename_size + extra_size]
        zip64_data, member_extra_fields = _parse_zip_central_directory_extra(
            extra,
            artifact=artifact,
        )
        extra_fields += member_extra_fields
        if extra_fields > expected_members * _ZIP_MAX_EXTRA_FIELDS_PER_MEMBER:
            raise ArchivePreflightError(
                f"{artifact} contains too many ZIP central directory extra fields"
            )
        _validate_zip_central_directory_zip64(header, zip64_data, artifact=artifact)
    if consumed != directory_size or members != expected_members:
        raise ArchivePreflightError(f"{artifact} has inconsistent ZIP central directory metadata")


def _validate_zip_central_directory_zip64(
    header: bytes,
    zip64_data: bytes | None,
    *,
    artifact: str,
) -> None:
    version_needed = struct.unpack_from("<H", header, 6)[0]
    compressed_size, uncompressed_size = struct.unpack_from("<2L", header, 20)
    local_header_offset = struct.unpack_from("<L", header, 42)[0]
    disk_number = struct.unpack_from("<H", header, 34)[0]
    zip64_size = 0
    for value in (uncompressed_size, compressed_size, local_header_offset):
        if value == _ZIP_UINT32_MAX:
            zip64_size += 8
    if disk_number == _ZIP_UINT16_MAX:
        zip64_size += 4

    if zip64_size == 0:
        if zip64_data is not None:
            raise ArchivePreflightError(
                f"{artifact} has unexpected ZIP64 central directory metadata"
            )
    elif zip64_data is None or len(zip64_data) != zip64_size:
        raise ArchivePreflightError(f"{artifact} has invalid ZIP64 central directory metadata")
    elif version_needed < _ZIP64_MINIMUM_VERSION:
        raise ArchivePreflightError(f"{artifact} has an invalid ZIP64 member version")

    if disk_number == _ZIP_UINT16_MAX and zip64_data is not None:
        disk_number = struct.unpack_from("<L", zip64_data, zip64_size - 4)[0]
    if disk_number != 0:
        raise ArchivePreflightError(f"{artifact} uses an unsupported multidisk ZIP")


def _parse_zip_central_directory_extra(
    extra: bytes,
    *,
    artifact: str,
) -> tuple[bytes | None, int]:
    offset = 0
    fields = 0
    zip64_data: bytes | None = None
    while offset < len(extra):
        fields += 1
        if len(extra) - offset < 4:
            raise ArchivePreflightError(f"{artifact} has invalid ZIP central directory metadata")
        header_id, data_size = struct.unpack_from("<2H", extra, offset)
        offset += 4
        data_end = offset + data_size
        if data_end > len(extra):
            raise ArchivePreflightError(f"{artifact} has invalid ZIP central directory metadata")
        if header_id == 0x0001:
            if zip64_data is not None:
                raise ArchivePreflightError(
                    f"{artifact} has duplicate ZIP64 central directory metadata"
                )
            zip64_data = extra[offset:data_end]
        offset = data_end
    return zip64_data, fields


def preflight_tar_gzip_stream(
    path: Path,
    *,
    artifact: str,
    maximum_members: int,
    maximum_file_bytes: int,
    maximum_archive_bytes: int = _DEFAULT_MAX_ARCHIVE_BYTES,
) -> ArchiveSnapshot:
    """Return a bounded gzip-compressed tar snapshot for ``tarfile``.

    Setuptools emits one PAX ``mtime`` record for each sdist member. This
    preflight accepts that timestamp metadata within archive-wide header, byte,
    record, and consecutive-chain limits, but rejects PAX keys that can replace
    paths, sizes, or link targets. ``tarfile`` recursively resolves consecutive
    PAX headers, so the chain limit stays well below Python's recursion limit.
    GNU long-name, long-link, and sparse extensions are rejected before their
    payloads are read. The caller's file-byte limit covers regular and
    special-member payloads; this scanner separately bounds TAR framing and the
    accepted PAX metadata before ``tarfile`` receives the snapshot.
    """
    snapshot = _read_archive_snapshot(
        path,
        artifact=artifact,
        maximum_bytes=maximum_archive_bytes,
    )
    maximum_pax_headers = min(_TAR_MAX_PAX_HEADERS, maximum_members + 1)
    maximum_stream_bytes = (
        maximum_file_bytes
        + (maximum_members * ((_TAR_BLOCK_BYTES - 1) + _TAR_BLOCK_BYTES))
        + _TAR_MAX_PAX_BYTES
        + (maximum_pax_headers * ((_TAR_BLOCK_BYTES - 1) + _TAR_BLOCK_BYTES))
        + (2 * _TAR_BLOCK_BYTES)
    )
    consumed = 0
    file_bytes = 0
    members = 0
    pax_bytes = 0
    pax_headers = 0
    pax_records = 0
    consecutive_pax_headers = 0
    try:
        with snapshot.open() as raw, gzip.GzipFile(fileobj=raw, mode="rb") as stream:
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
                    if pax_headers > maximum_pax_headers:
                        raise ArchivePreflightError(
                            f"{artifact} contains too many PAX metadata headers"
                        )
                    consecutive_pax_headers += 1
                    if consecutive_pax_headers > _TAR_MAX_CONSECUTIVE_PAX_HEADERS:
                        raise ArchivePreflightError(
                            f"{artifact} contains too many consecutive PAX metadata headers"
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
                    pax_records = _validate_pax_payload(
                        payload[:member_size],
                        artifact=artifact,
                        previous_records=pax_records,
                    )
                    continue

                consecutive_pax_headers = 0
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
) -> ArchiveSnapshot:
    """Return a bounded image of one unchanged regular-file identity."""
    descriptor = -1
    try:
        before_open = path.lstat()
        if not stat.S_ISREG(before_open.st_mode):
            raise ArchivePreflightError(f"{artifact} must be a regular, non-symlink file")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before_open, opened):
            raise ArchivePreflightError(f"{artifact} changed while it was opened")
        if opened.st_size > maximum_bytes:
            raise ArchivePreflightError(f"{artifact} exceeds the compressed byte limit")

        content = bytearray(min(maximum_bytes + 1, opened.st_size + 1))
        content_size = 0
        while content_size < len(content):
            chunk = os.read(
                descriptor,
                min(1024 * 1024, len(content) - content_size),
            )
            if not chunk:
                break
            chunk_end = content_size + len(chunk)
            content[content_size:chunk_end] = chunk
            content_size = chunk_end
        del content[content_size:]
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
    return ArchiveSnapshot(content)


def _padded_tar_size(size: int) -> int:
    return ((size + _TAR_BLOCK_BYTES - 1) // _TAR_BLOCK_BYTES) * _TAR_BLOCK_BYTES


def _validate_pax_payload(
    payload: bytes,
    *,
    artifact: str,
    previous_records: int,
) -> int:
    offset = 0
    records = previous_records
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
    return records


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
