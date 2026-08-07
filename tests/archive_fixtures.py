"""Helpers for constructing adversarial archive fixtures."""

from __future__ import annotations

import gzip
import struct
import tarfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZipRecordName = Literal["classic", "zip64", "locator"]
ZipCentralDirectoryUint32Field = Literal[
    "compressed_size",
    "uncompressed_size",
    "local_header_offset",
]


@dataclass(frozen=True)
class _ZipRecordLayout:
    signature: bytes
    structure: struct.Struct
    fields: tuple[str, ...]


_ZIP_RECORD_LAYOUTS = {
    "classic": _ZipRecordLayout(
        signature=_ZIP_EOCD_SIGNATURE,
        structure=struct.Struct("<4s4H2LH"),
        fields=(
            "signature",
            "disk_number",
            "directory_disk",
            "disk_members",
            "total_members",
            "directory_size",
            "directory_offset",
            "comment_size",
        ),
    ),
    "zip64": _ZipRecordLayout(
        signature=_ZIP64_EOCD_SIGNATURE,
        structure=struct.Struct("<4sQ2H2L4Q"),
        fields=(
            "signature",
            "record_size",
            "version_made_by",
            "version_needed",
            "disk_number",
            "directory_disk",
            "disk_members",
            "total_members",
            "directory_size",
            "directory_offset",
        ),
    ),
    "locator": _ZipRecordLayout(
        signature=_ZIP64_LOCATOR_SIGNATURE,
        structure=struct.Struct("<4sLQL"),
        fields=("signature", "record_disk", "record_offset", "total_disks"),
    ),
}
_ZIP_CENTRAL_DIRECTORY_UINT32_OFFSETS = {
    "compressed_size": 20,
    "uncompressed_size": 24,
    "local_header_offset": 42,
}


def _zip_record_layout(record: ZipRecordName) -> _ZipRecordLayout:
    return _ZIP_RECORD_LAYOUTS[record]


def zip_record_offset(path: Path, *, record: ZipRecordName) -> int:
    """Return the offset of a named ZIP end record in a fixture."""
    contents = path.read_bytes()
    classic = _zip_record_layout("classic")
    search_end = len(contents)
    classic_offset = -1
    while search_end:
        candidate = contents.rfind(classic.signature, 0, search_end)
        if candidate < 0:
            break
        if candidate + classic.structure.size <= len(contents):
            values = classic.structure.unpack_from(contents, candidate)
            comment_size = int(values[classic.fields.index("comment_size")])
            if candidate + classic.structure.size + comment_size == len(contents):
                classic_offset = candidate
                break
        search_end = candidate
    if classic_offset < 0:
        raise ValueError("ZIP fixture has no structurally valid classic record")
    if record == "classic":
        return classic_offset

    locator = _zip_record_layout("locator")
    locator_offset = classic_offset - locator.structure.size
    if locator_offset < 0 or contents[locator_offset : locator_offset + 4] != locator.signature:
        raise ValueError("ZIP fixture has no structurally positioned locator record")
    if record == "locator":
        return locator_offset

    locator_values = locator.structure.unpack_from(contents, locator_offset)
    zip64_offset = int(locator_values[locator.fields.index("record_offset")])
    zip64 = _zip_record_layout("zip64")
    if (
        zip64_offset < 0
        or zip64_offset + zip64.structure.size > locator_offset
        or contents[zip64_offset : zip64_offset + 4] != zip64.signature
    ):
        raise ValueError("ZIP fixture has no structurally positioned ZIP64 record")
    return zip64_offset


def read_zip_record_field(path: Path, *, record: ZipRecordName, field: str) -> int:
    """Read one numeric field from a named ZIP end record."""
    layout = _zip_record_layout(record)
    try:
        field_index = layout.fields.index(field)
    except ValueError as exc:
        raise ValueError(f"Unknown {record} ZIP field: {field}") from exc
    if field == "signature":
        raise ValueError("Use replace_zip_record_signature for signatures")
    contents = path.read_bytes()
    record_offset = zip_record_offset(path, record=record)
    values = layout.structure.unpack_from(contents, record_offset)
    return int(values[field_index])


def update_zip_record(path: Path, *, record: ZipRecordName, **fields: int) -> None:
    """Set numeric fields on a named ZIP end record."""
    layout = _zip_record_layout(record)
    contents = bytearray(path.read_bytes())
    record_offset = zip_record_offset(path, record=record)
    values = list(layout.structure.unpack_from(contents, record_offset))
    for field, value in fields.items():
        try:
            field_index = layout.fields.index(field)
        except ValueError as exc:
            raise ValueError(f"Unknown {record} ZIP field: {field}") from exc
        if field == "signature":
            raise ValueError("Use replace_zip_record_signature for signatures")
        values[field_index] = value
    layout.structure.pack_into(contents, record_offset, *values)
    path.write_bytes(contents)


def replace_zip_record_signature(
    path: Path,
    *,
    record: ZipRecordName,
    signature: bytes,
) -> None:
    """Replace a named ZIP end-record signature with four fixture bytes."""
    if len(signature) != 4:
        raise ValueError("ZIP record signatures must contain four bytes")
    contents = bytearray(path.read_bytes())
    record_offset = zip_record_offset(path, record=record)
    contents[record_offset : record_offset + 4] = signature
    path.write_bytes(contents)


def zip64_extensible_data_block(header_id: int, data: bytes) -> bytes:
    """Encode one ZIP64 extensible-data block."""
    return struct.pack("<HL", header_id, len(data)) + data


def append_ambiguous_zip_eocd(path: Path) -> None:
    """Append a malformed EOCD signature within the valid EOCD comment."""
    classic = _zip_record_layout("classic")
    ambiguous_record = classic.structure.pack(
        _ZIP_EOCD_SIGNATURE,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    )
    update_zip_record(path, record="classic", comment_size=len(ambiguous_record))
    with path.open("ab") as stream:
        stream.write(ambiguous_record)


def add_zip64_end_records(
    path: Path,
    *,
    disk_members: int | None = None,
    total_members: int | None = None,
    directory_size: int | None = None,
    directory_offset: int | None = None,
    extensible_data: bytes = b"",
) -> None:
    """Insert consistent ZIP64 end records before a classic ZIP end record."""
    contents = bytearray(path.read_bytes())
    eocd_offset = contents.rfind(_ZIP_EOCD_SIGNATURE)
    if eocd_offset < 0:
        raise ValueError("ZIP fixture has no classic end record")
    (
        _signature,
        _disk_number,
        _directory_disk,
        classic_disk_members,
        classic_total_members,
        classic_directory_size,
        classic_directory_offset,
        _comment_size,
    ) = _zip_record_layout("classic").structure.unpack_from(contents, eocd_offset)
    record = (
        _zip_record_layout("zip64").structure.pack(
            _ZIP64_EOCD_SIGNATURE,
            44 + len(extensible_data),
            45,
            45,
            0,
            0,
            classic_disk_members if disk_members is None else disk_members,
            classic_total_members if total_members is None else total_members,
            classic_directory_size if directory_size is None else directory_size,
            classic_directory_offset if directory_offset is None else directory_offset,
        )
        + extensible_data
    )
    locator = _zip_record_layout("locator").structure.pack(
        _ZIP64_LOCATOR_SIGNATURE,
        0,
        eocd_offset,
        1,
    )
    contents[eocd_offset:eocd_offset] = record + locator
    path.write_bytes(contents)


def write_empty_member_zip(path: Path, *, members: int) -> None:
    """Write a valid ZIP whose members have distinct names and empty payloads."""
    write_empty_member_zip_with_extra(path, members=members, extra=b"")


def write_empty_member_zip_with_extra(
    path: Path,
    *,
    members: int,
    extra: bytes,
) -> None:
    """Write a valid empty-member ZIP with identical per-member extra data."""
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(members):
            member = zipfile.ZipInfo(f"empty/{index}")
            member.extra = extra
            archive.writestr(member, b"")


def write_central_directory_disk_zip(
    path: Path,
    *,
    disk_number: int,
    extra: bytes = b"",
    zip64_fields: Sequence[ZipCentralDirectoryUint32Field] = (),
    version_needed: int | None = None,
) -> None:
    """Write one member and set its central-directory disk metadata."""
    member = zipfile.ZipInfo("member")
    member.extra = extra
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, b"")

    central_offset = read_zip_record_field(
        path,
        record="classic",
        field="directory_offset",
    )
    contents = bytearray(path.read_bytes())
    for field in zip64_fields:
        struct.pack_into(
            "<L",
            contents,
            central_offset + _ZIP_CENTRAL_DIRECTORY_UINT32_OFFSETS[field],
            0xFFFFFFFF,
        )
    if version_needed is None and (zip64_fields or disk_number == 0xFFFF):
        version_needed = 45
    if version_needed is not None:
        struct.pack_into("<H", contents, central_offset + 6, version_needed)
    struct.pack_into("<H", contents, central_offset + 34, disk_number)
    path.write_bytes(contents)


def set_zip_central_directory_uint32_sentinels(
    path: Path,
    *,
    member_index: int,
    fields: Sequence[ZipCentralDirectoryUint32Field],
) -> None:
    """Set selected 32-bit fields on one central-directory member to ZIP64 sentinels."""
    central_offset = read_zip_record_field(
        path,
        record="classic",
        field="directory_offset",
    )
    contents = bytearray(path.read_bytes())
    member_offset = central_offset
    for _ in range(member_index):
        if contents[member_offset : member_offset + 4] != b"PK\x01\x02":
            raise ValueError("member index exceeds the ZIP central directory")
        filename_size, extra_size, comment_size = struct.unpack_from(
            "<3H",
            contents,
            member_offset + 28,
        )
        member_offset += 46 + filename_size + extra_size + comment_size
    if contents[member_offset : member_offset + 4] != b"PK\x01\x02":
        raise ValueError("member index exceeds the ZIP central directory")
    for field in fields:
        struct.pack_into(
            "<L",
            contents,
            member_offset + _ZIP_CENTRAL_DIRECTORY_UINT32_OFFSETS[field],
            0xFFFFFFFF,
        )
    path.write_bytes(contents)


def pax_record(key: str, value: str) -> bytes:
    """Encode one PAX record with its self-inclusive decimal length."""
    body = f"{key}={value}\n".encode()
    size = len(body) + 2
    while True:
        encoded = f"{size} ".encode() + body
        if len(encoded) == size:
            return encoded
        size = len(encoded)


def write_extension_tar_gzip(
    path: Path,
    *,
    extension_type: bytes,
    extension_payload: bytes,
) -> None:
    """Write a gzip tar containing one extension header and one regular member."""
    write_extension_chain_tar_gzip(
        path,
        extensions=((extension_type, extension_payload),),
    )


def write_extension_chain_tar_gzip(
    path: Path,
    *,
    extensions: Sequence[tuple[bytes, bytes]],
) -> None:
    """Write a gzip tar containing extension headers and one regular member."""
    member = tarfile.TarInfo("vexcalibur-0.1.0/PKG-INFO")
    metadata = b"Name: vexcalibur\nVersion: 0.1.0\n"
    member.size = len(metadata)

    with gzip.open(path, "wb") as archive:
        for extension_type, extension_payload in extensions:
            extension = tarfile.TarInfo("././@PaxHeader")
            extension.type = extension_type
            extension.size = len(extension_payload)
            archive.write(extension.tobuf(format=tarfile.USTAR_FORMAT))
            archive.write(extension_payload)
            archive.write(b"\0" * (-len(extension_payload) % tarfile.BLOCKSIZE))
        archive.write(member.tobuf(format=tarfile.USTAR_FORMAT))
        archive.write(metadata)
        archive.write(b"\0" * (-len(metadata) % tarfile.BLOCKSIZE))
        archive.write(b"\0" * (2 * tarfile.BLOCKSIZE))
