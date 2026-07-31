"""Bound archive metadata before Python materializes archive members."""

from __future__ import annotations

import gzip
import math
import struct
from pathlib import Path

_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_SIZE = 22
_ZIP_MAX_COMMENT_BYTES = 65_535
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_TAR_BLOCK_BYTES = 512
_TAR_PAX_TYPES = frozenset({b"g", b"x"})
_TAR_REJECTED_EXTENSION_TYPES = frozenset({b"K", b"L", b"S"})
_TAR_MAX_PAX_BYTES = 1024 * 1024
_TAR_MAX_PAX_RECORDS = 10_000
_TAR_ALLOWED_PAX_KEYS = frozenset({b"mtime"})


class ArchivePreflightError(ValueError):
    """Raised when an archive exceeds a pre-materialization boundary."""


def preflight_zip_member_count(
    path: Path,
    *,
    artifact: str,
    maximum_members: int,
    maximum_directory_bytes: int,
) -> None:
    """Reject ZIP metadata floods before ``zipfile`` constructs ``ZipInfo`` objects."""
    size = path.stat().st_size
    tail_size = min(size, _ZIP_EOCD_SIZE + _ZIP_MAX_COMMENT_BYTES)
    with path.open("rb") as stream:
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
        path,
        artifact=artifact,
        directory_offset=directory_offset,
        directory_size=directory_size,
        expected_members=total_members,
        maximum_members=maximum_members,
    )


def _preflight_zip_central_directory(
    path: Path,
    *,
    artifact: str,
    directory_offset: int,
    directory_size: int,
    expected_members: int,
    maximum_members: int,
) -> None:
    consumed = 0
    members = 0
    with path.open("rb") as stream:
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
                raise ArchivePreflightError(
                    f"{artifact} has an invalid ZIP central directory boundary"
                )
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
) -> None:
    """Bound a gzip-compressed tar stream before ``tarfile`` reads it.

    Setuptools emits one PAX ``mtime`` record for each sdist member. This
    preflight accepts that bounded timestamp metadata but rejects PAX keys that
    can replace paths, sizes, or link targets. GNU long-name, long-link, and
    sparse extensions are rejected for the same reason.
    """
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
        with path.open("rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as stream:
            while True:
                header, consumed = _read_bounded(
                    stream,
                    _TAR_BLOCK_BYTES,
                    consumed=consumed,
                    maximum=maximum_stream_bytes,
                    artifact=artifact,
                )
                if not header:
                    return
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
